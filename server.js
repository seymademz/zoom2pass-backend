// server.js

// CORE NODE MODULES
require('dotenv').config(); 
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors'); // <--- 1. CORS IMPORTED

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // This forces SSL for Render while you're on your local Mac
    ssl: { rejectUnauthorized: false } 
});

// ==========================================================
// 1. MIDDLEWARE SETUP (CORS and HMAC/Body Handling)
// ==========================================================

// 2. APPLY CORS: Allows frontend (React) requests from any origin during development.
app.use(cors({ origin: '*' })); 

// Custom body parsing for the webhook route (to get the RAW body buffer for security check)
// Applied only to the webhook route to avoid interference with other endpoints
const rawBodyMiddleware = bodyParser.raw({ type: 'application/json' });

// HMAC Webhook Verification Middleware 
const verifyShopifyWebhook = (req, res, next) => {
    const shopifyHmac = req.get('X-Shopify-Hmac-Sha256');
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

    // Development Bypass (If secret or HMAC is missing)
    if (!secret || !shopifyHmac) {
        if (req.body && req.body.toString) {
             req.body = JSON.parse(req.body.toString()); // Manually parse the body
        }
        console.warn('Webhook received without SECRET/HMAC. Bypassing security check.');
        return next(); 
    }

    // Actual Verification Logic
    if (!shopifyHmac) {
        return res.status(401).send('Unauthorized: Missing signature header.');
    }
    
    const hash = crypto
        .createHmac('sha256', secret)
        .update(req.body)
        .digest('base64');

    if (hash !== shopifyHmac) {
        console.error('HMAC verification failed!');
        return res.status(401).send('Unauthorized: HMAC verification failed.');
    }
    
    // Verification passed: Manually parse the body buffer
    req.body = JSON.parse(req.body.toString());
    next();
};


// Global JSON middleware (applied to ALL API routes *except* the webhook)
app.use((req, res, next) => {
    if (req.originalUrl.startsWith('/api/webhooks/shopify-order')) {
        return next();
    }
    bodyParser.json({ limit: '10mb' })(req, res, next);
});


// Simple health check route
app.get('/', (req, res) => {
    res.send('Zoom2Pass Backend API is running!');
});


// ==========================================================
// 2. SHOPIFY WEBHOOK RECEIVER (Order Payment)
// ==========================================================

// Full URL: https://driving-course-backend.onrender.com/api/webhooks/shopify-order
app.post('/api/webhooks/shopify-order', rawBodyMiddleware, verifyShopifyWebhook, async (req, res) => {
    
    const order = req.body;
    
    if (order.financial_status !== 'paid') {
        return res.status(200).send('Skipping assignment, not paid.');
    }

    const orderId = String(order.id);
    const customerName = `${order.shipping_address?.first_name || ''} ${order.shipping_address?.last_name || ''}`.trim();
    // --- ADDED FOR STUDENT PORTAL ---
    const customerEmail = order.customer?.email || order.email; 
    // --------------------------------
    const rawPostcode = order.shipping_address?.zip; 
    const courseTitle = order.line_items?.[0]?.title || 'Unknown Course'; 
    
    if (!rawPostcode || !orderId) {
        return res.status(200).send('Webhook received, data incomplete.');
    }

    try {
        // --- UPDATED QUERY TO INCLUDE EMAIL ---
        const query = `
            INSERT INTO assignments (order_id, customer_name, customer_email, course_title, postcode, status)
            VALUES ($1, $2, $3, $4, $5, 'Unassigned')
            ON CONFLICT (order_id) DO NOTHING;
        `;
        const values = [orderId, customerName, customerEmail, courseTitle, rawPostcode];
        
        await pool.query(query, values);

        // --- NEW: ENSURE USER ROLE IS INITIALIZED AS STUDENT ---
        if (customerEmail) {
            await pool.query(`
                INSERT INTO users (email, role, first_name, last_name)
                VALUES ($1, 'student', $2, $3)
                ON CONFLICT (email) DO NOTHING;
            `, [customerEmail.toLowerCase().trim(), order.shipping_address?.first_name, order.shipping_address?.last_name]);
        }
        
        console.log(`[SUCCESS] Assignment created for Order ${orderId} (${rawPostcode})`);
        res.status(200).send('Webhook successfully processed.');

    } catch (error) {
        console.error('Database Error during webhook processing:', error);
        res.status(500).send('Internal Server Error: Could not save assignment.');
    }
});


// ==========================================================
// 3. INSTRUCTOR PORTAL API ENDPOINTS
// ==========================================================

// 3.1 POST: Save Instructor Service Areas
app.post('/api/instructor/:id/areas', async (req, res) => {
    const instructorId = req.params.id;
    const { service_areas } = req.body; 

    if (!Array.isArray(service_areas)) return res.status(400).send({ message: "Areas must be an array." });

    try {
        const query = `UPDATE instructors SET service_areas = $1::jsonb WHERE id = $2 RETURNING service_areas;`;
        // Make sure you are stringifying the array
const result = await pool.query(query, [JSON.stringify(service_areas), instructorId]);

        if (result.rowCount === 0) return res.status(404).send({ message: "Instructor not found." });

        res.status(200).send({ message: "Areas updated.", areas: result.rows[0].service_areas });
    } catch (error) {
        console.error('Error saving areas:', error);
        res.status(500).send({ message: "Failed to update service areas." });
    }
});

// 3.2 GET: Fetch Instructor Service Areas
app.get('/api/instructor/:id/areas', async (req, res) => {
    const instructorId = req.params.id;
    try {
        const result = await pool.query(`SELECT service_areas FROM instructors WHERE id = $1;`, [instructorId]);
        
        if (result.rowCount === 0) return res.status(404).send({ message: "Instructor not found." });

        res.status(200).send({ service_areas: result.rows[0].service_areas || [] });
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch service areas." });
    }
});

// 3.3 GET: List Available Assignments (Filtered by Area)
app.get('/api/assignments/available/:instructorId', async (req, res) => {
    // FIX APPLIED HERE: Changed req.params.id to req.params.instructorId
    const instructorId = req.params.instructorId; 
    
    try {
        const instructorResult = await pool.query(`SELECT service_areas FROM instructors WHERE id = $1`, [instructorId]);
        const areas = instructorResult.rows[0]?.service_areas || [];
        
        if (areas.length === 0) return res.status(200).send([]);
        
        const conditions = areas.map((area, index) => `postcode LIKE $${index + 2} || '%'`).join(' OR ');
        const values = ['Unassigned', ...areas]; 

        const assignmentQuery = `
            SELECT id, customer_name, course_title, postcode, created_at, order_id
            FROM assignments
            WHERE status = $1 AND (${conditions})
            ORDER BY created_at ASC;
        `;
        
        const assignmentsResult = await pool.query(assignmentQuery, values);
        res.status(200).send(assignmentsResult.rows);

    } catch (error) {
        console.error('Error fetching available assignments:', error);
        res.status(500).send({ message: "Failed to fetch available assignments." });
    }
});

// 3.4 POST: Atomically Claim Assignment
app.post('/api/assignments/:id/accept', async (req, res) => {
    const assignmentId = req.params.id;
    const { instructorId } = req.body; 

    if (!instructorId) return res.status(400).send({ message: "Instructor ID is required." });

    try {
        const query = `
            UPDATE assignments
            SET status = 'Assigned', assigned_instructor_id = $1
            WHERE id = $2 AND status = 'Unassigned'
            RETURNING *;
        `;
        
        const result = await pool.query(query, [instructorId, assignmentId]);

        if (result.rowCount === 0) {
            return res.status(409).send({ 
                message: "This assignment is no longer available. It may have been claimed by another instructor." 
            });
        }
        
        res.status(200).send({ 
            message: "Assignment successfully claimed!",
            assignment: result.rows[0]
        });

    } catch (error) {
        console.error('Error claiming assignment:', error);
        res.status(500).send({ message: "Failed to claim assignment due to server error." });
    }
});

// 3.5 GET: List Assigned Courses for a specific Instructor
app.get('/api/assignments/assigned/:instructorId', async (req, res) => {
    const instructorId = req.params.instructorId;

    try {
        const query = `
            SELECT id, customer_name, course_title, postcode, status, created_at, order_id, notes, lessons_completed
            FROM assignments
            WHERE assigned_instructor_id = $1 AND status = 'Assigned'
            ORDER BY created_at DESC;
        `;
        
        const result = await pool.query(query, [instructorId]);

        res.status(200).send(result.rows);

    } catch (error) {
        console.error('Error fetching assigned courses:', error);
        res.status(500).send({ message: "Failed to fetch assigned courses." });
    }
});

// 3.6 PUT: Update Assignment Progress and Notes (Notes now appended to JSONB array)
app.put('/api/assignments/:id/update_progress', async (req, res) => {
    const assignmentId = req.params.id;
    // Assuming `notes` holds the NEW note content and not the entire array
    const { notes: newNoteContent, lessonsCompleted } = req.body; 

    // Validation for Lessons Completed (always required)
    if (typeof lessonsCompleted === 'undefined') {
        return res.status(400).send({ message: "Lessons completed field is required." });
    }
    
    // Ensure lessonsCompleted is an integer
    const lessons = parseInt(lessonsCompleted, 10);
    if (isNaN(lessons) || lessons < 0) {
        return res.status(400).send({ message: "Lessons completed must be a non-negative number." });
    }

    // Start building the query components
    let setClauses = [`lessons_completed = $1`, `updated_at = NOW()`];
    let values = [lessons];
    let queryIndex = 2; // lessonsCompleted is $1

    // Handle Notes Append
    if (newNoteContent && newNoteContent.trim() !== "") {
        const newNoteObject = {
            content: newNoteContent.trim(),
            timestamp: new Date().toISOString()
        };
        
        // Append the new note object (as a JSON string) to the existing JSONB array
        setClauses.push(`notes = notes || $${queryIndex}::jsonb`);
        values.push(JSON.stringify(newNoteObject));
        queryIndex++;
    }
    
    values.push(assignmentId); // Assignment ID is the last parameter

    if (setClauses.length === 0) {
        return res.status(400).send({ message: "No fields provided for update." });
    }

    try {
        const query = `
            UPDATE assignments
            SET ${setClauses.join(', ')}
            WHERE id = $${queryIndex}
            RETURNING *;
        `;
        
        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).send({ message: "Assignment not found." });
        }
        
        res.status(200).send({ 
            message: "Progress and notes updated successfully.",
            assignment: result.rows[0]
        });

    } catch (error) {
        console.error('Error updating assignment progress:', error);
        res.status(500).send({ message: "Failed to update assignment progress due to server error." });
    }
});

// 3.7 GET: Fetch Instructor Schedule Events (NEW)
app.get('/api/instructor/:id/schedule', async (req, res) => {
    const instructorId = req.params.id;
    try {
        // NOTE: Assumes 'schedule_events' is a JSONB column on the 'instructors' table, defaulting to '[]'
        const result = await pool.query(`SELECT schedule_events FROM instructors WHERE id = $1;`, [instructorId]);
        
        if (result.rowCount === 0) return res.status(404).send({ message: "Instructor not found." });

        res.status(200).send({ schedule_events: result.rows[0].schedule_events || [] });
    } catch (error) {
        console.error('Error fetching schedule:', error);
        res.status(500).send({ message: "Failed to fetch schedule." });
    }
});

// 3.8 POST: Add Instructor Schedule Event (NEW - Appends to JSONB array)
app.post('/api/instructor/:id/schedule', async (req, res) => {
    const instructorId = req.params.id;
    const newEvent = req.body; 

    if (!newEvent || !newEvent.dateTime || !newEvent.title) {
        return res.status(400).send({ message: "Event data is incomplete." });
    }
    
    // Ensure the event data is stored as a JSON string to be appended correctly
    const newEventJson = JSON.stringify(newEvent);
    
    try {
        // Use the JSONB concatenation operator (||) to append the new event object
        const query = `
            UPDATE instructors
            SET schedule_events = COALESCE(schedule_events, '[]'::jsonb) || $1::jsonb
            WHERE id = $2
            RETURNING schedule_events;
        `;
        
        const result = await pool.query(query, [newEventJson, instructorId]);

        if (result.rowCount === 0) {
            return res.status(404).send({ message: "Instructor not found." });
        }
        
        res.status(200).send({ 
            message: "Event added successfully!",
            schedule_events: result.rows[0].schedule_events
        });

    } catch (error) {
        console.error('Error adding schedule event:', error);
        res.status(500).send({ message: "Failed to add schedule event due to server error." });
    }
});

// ==========================================================
// 4. STUDENT PORTAL API ENDPOINTS (APPENDED)
// ==========================================================

// 4.1 GET: Fetch Assignment by Student Email (Updated with Instructor JOIN)
app.get('/api/assignments/student/:email', async (req, res) => {
    const studentEmail = req.params.email;
    try {
        const query = `
            SELECT 
                a.id, a.customer_name, a.course_title, a.postcode, a.status, 
                a.created_at, a.order_id, a.notes, a.lessons_completed, a.assigned_instructor_id,
                i.phone AS instructor_phone,
                i.firstname AS instructor_first_name
            FROM assignments a
            LEFT JOIN instructors i ON a.assigned_instructor_id = i.id
            WHERE a.customer_email = $1
            ORDER BY a.created_at DESC
            LIMIT 1;
        `;
        const result = await pool.query(query, [studentEmail]);

        if (result.rowCount === 0) {
            return res.status(404).send({ message: "No course found for this email." });
        }
        res.status(200).send(result.rows[0]);
    } catch (error) {
        console.error('Error fetching student course:', error);
        res.status(500).send({ message: "Server error fetching course details." });
    }
});

// ==========================================================
// 5. USER MANAGEMENT & AUTH (NEW - CROSS-DEVICE SUPPORT)
// ==========================================================

// 5.1 GET: Fetch User Role by Email
app.get('/api/users/role/:email', async (req, res) => {
    const email = req.params.email.toLowerCase().trim();
    try {
        const result = await pool.query('SELECT role, first_name, last_name FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ message: "User not found" });
        }
    } catch (err) {
        console.error('Error fetching user role:', err);
        res.status(500).send("Server Error");
    }
});

// 5.2 POST: Create/Register New User Role
app.post('/api/users/register', async (req, res) => {
    const { email, firstName, lastName, role } = req.body;
    if (!email || !role) return res.status(400).send({ message: "Email and Role are required." });

    try {
        await pool.query(`
            INSERT INTO users (email, first_name, last_name, role)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (email) DO UPDATE 
            SET first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name, role = EXCLUDED.role;
        `, [email.toLowerCase().trim(), firstName, lastName, role]);

        res.status(200).send({ message: "User registered successfully." });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send({ message: "Failed to register user." });
    }
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});