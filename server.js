// server/server.js (Final, Consolidated, and Correct Version)

// 1. IMPORTS
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// 2. INITIALIZATION
const app = express();
const PORT = process.env.PORT || 5000;

// 3. MIDDLEWARE
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 4. DATABASE CONNECTION
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));

// 5. SESSION MANAGEMENT
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: 'sessions'
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

// 6. MONGOOSE SCHEMAS & MODELS
const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, default: 'admin' },
    password: { type: String, required: true }
});
const Admin = mongoose.model('Admin', AdminSchema, 'admins');

const HospitalSchema = new mongoose.Schema({
    hospitalName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    address: { type: String },
    phone: { type: String },
    details: {
        oxygenCylinders: { total: { type: Number, default: 0 } },
        bloodAvailability: {
            'A+': { type: Number, default: 0 }, 'A-': { type: Number, default: 0 },
            'B+': { type: Number, default: 0 }, 'B-': { type: Number, default: 0 },
            'AB+': { type: Number, default: 0 }, 'AB-': { type: Number, default: 0 },
            'O+': { type: Number, default: 0 }, 'O-': { type: Number, default: 0 },
        },
        organAvailability: [{
            organName: { type: String, required: true, enum: ['Kidney', 'Liver', 'Heart', 'Lung', 'Pancreas', 'Cornea'] },
            bloodGroup: { type: String, required: true, enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'] },
            age: { type: Number, required: true },
            notes: { type: String }
        }]
    }
}, { timestamps: true });
const Hospital = mongoose.model('Hospital', HospitalSchema, 'hospitals');

const RequestSchema = new mongoose.Schema({
    requestingHospital: { type: mongoose.Schema.Types.ObjectId, ref: 'Hospital', required: true },
    providingHospital: { type: mongoose.Schema.Types.ObjectId, ref: 'Hospital' },
    requestType: { type: String, enum: ['Oxygen', 'Blood', 'Organ'], required: true },
    status: { type: String, enum: ['Open', 'Accepted', 'Closed', 'Rejected'], default: 'Open' },
    details: {
        bloodGroup: { type: String, enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'] },
        quantity: { type: Number },
        organName: { type: String, enum: ['Kidney', 'Liver', 'Heart', 'Lung', 'Pancreas', 'Cornea'] },
    },
    description: { type: String, required: true },
}, { timestamps: true });
const Request = mongoose.model('Request', RequestSchema, 'requests');

const KnowledgeArticleSchema = new mongoose.Schema({
    postingHospital: { type: mongoose.Schema.Types.ObjectId, ref: 'Hospital', required: true },
    title: { type: String, required: true },
    category: { type: String, required: true, enum: ['Clinical', 'Administrative', 'Operational', 'Other'] },
    content: { type: String, required: true },
}, { timestamps: true });
const KnowledgeArticle = mongoose.model('KnowledgeArticle', KnowledgeArticleSchema, 'knowledge_articles');

// 7. API ROUTES
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).json({ message: 'Unauthorized' });
};

// --- AUTHENTICATION ROUTES ---
app.post('/api/hospital/register', async (req, res) => {
    try {
        const { hospitalName, email, password } = req.body;
        const existingHospital = await Hospital.findOne({ email });
        if (existingHospital) {
            return res.status(400).json({ message: 'Hospital with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newHospital = new Hospital({ hospitalName, email, password: hashedPassword });
        await newHospital.save();
        res.status(201).json({ message: 'Hospital registered successfully.' });
    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, userType } = req.body;
        let user;
        if (userType === 'hospital') {
            user = await Hospital.findOne({ email });
        } else if (userType === 'admin') {
            user = await Admin.findOne({ username: email });
        }
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        req.session.userId = user._id;
        req.session.userType = userType;
        req.session.name = user.hospitalName || user.username;
        res.status(200).json({
            message: 'Login successful',
            user: { id: user._id, type: userType, name: req.session.name }
        });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logout successful' });
    });
});

app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.status(200).json({ isAuthenticated: true, user: { id: req.session.userId, type: req.session.userType, name: req.session.name } });
    } else {
        res.status(200).json({ isAuthenticated: false });
    }
});

// --- HOSPITAL & RESOURCE ROUTES ---
app.get('/api/hospital/details', isAuthenticated, async (req, res) => {
    if (req.session.userType !== 'hospital') return res.status(403).json({ message: 'Access denied.' });
    try {
        const hospital = await Hospital.findById(req.session.userId).select('-password');
        if (!hospital) return res.status(404).json({ message: 'Hospital not found.' });
        res.json(hospital);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/hospital/details', isAuthenticated, async (req, res) => {
    if (req.session.userType !== 'hospital') return res.status(403).json({ message: 'Access denied.' });
    try {
        const updatedHospital = await Hospital.findByIdAndUpdate(req.session.userId, req.body, { new: true }).select('-password');
        res.json({ message: 'Details updated successfully', hospital: updatedHospital });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/hospitals/search', isAuthenticated, async (req, res) => {
    try {
        const { requestType, bloodGroup, organName, quantity } = req.query;
        const query = {};
        if (requestType === 'Blood') {
            if (!bloodGroup || !quantity) return res.status(400).json({ message: 'Blood group and quantity are required.' });
            query[`details.bloodAvailability.${bloodGroup}`] = { $gte: parseInt(quantity) };
        } else if (requestType === 'Oxygen') {
            if (!quantity) return res.status(400).json({ message: 'Quantity is required.' });
            query['details.oxygenCylinders.total'] = { $gte: parseInt(quantity) };
        } else if (requestType === 'Organ') {
            if (!organName || !bloodGroup) return res.status(400).json({ message: 'Organ name and blood group are required.' });
            query['details.organAvailability'] = { $elemMatch: { organName, bloodGroup } };
        } else {
            return res.status(400).json({ message: 'Invalid request type' });
        }
        query._id = { $ne: req.session.userId };
        const hospitals = await Hospital.find(query).select('hospitalName address phone');
        res.json(hospitals);
    } catch (error) {
        console.error('Search Error:', error);
        res.status(500).json({ message: 'Server error during search' });
    }
});

// --- RESOURCE REQUEST ROUTES ---
app.post('/api/requests', isAuthenticated, async (req, res) => {
    try {
        const newRequest = new Request({
            ...req.body,
            requestingHospital: req.session.userId
        });
        await newRequest.save();
        res.status(201).json({ message: 'Request posted successfully', request: newRequest });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/requests', isAuthenticated, async (req, res) => {
    try {
        const requests = await Request.find()
            .populate('requestingHospital', 'hospitalName')
            .populate('providingHospital', 'hospitalName')
            .sort({ createdAt: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/requests/accept', isAuthenticated, async (req, res) => {
    const { requestId } = req.body;
    const providerHospitalId = req.session.userId;
    try {
        const request = await Request.findById(requestId);
        if (!request) return res.status(404).json({ message: 'Request not found.' });
        if (request.status !== 'Open') return res.status(400).json({ message: 'This request is no longer open.' });
        if (request.requestingHospital.toString() === providerHospitalId) {
            return res.status(400).json({ message: 'You cannot accept your own request.' });
        }
        
        const update = {};
        if (request.requestType === 'Blood') {
            update.$inc = { [`details.bloodAvailability.${request.details.bloodGroup}`]: -request.details.quantity };
        } else if (request.requestType === 'Oxygen') {
            update.$inc = { 'details.oxygenCylinders.total': -request.details.quantity };
        } else if (request.requestType === 'Organ') {
            update.$pull = { 'details.organAvailability': { organName: request.details.organName, bloodGroup: request.details.bloodGroup } };
        }
        
        await Hospital.findByIdAndUpdate(providerHospitalId, update);
        await Request.findByIdAndUpdate(requestId, {
            status: 'Accepted',
            providingHospital: providerHospitalId
        });
        
        res.status(200).json({ message: 'Request accepted! Your inventory has been updated.' });
    } catch (error) {
        console.error("Acceptance Error:", error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

app.post('/api/requests/cancel', isAuthenticated, async (req, res) => {
    const { requestId } = req.body;
    try {
        const request = await Request.findById(requestId);
        if (!request) return res.status(404).json({ message: 'Request not found.' });
        if (request.requestingHospital.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Not authorized' });
        }
        await Request.findByIdAndDelete(requestId);
        res.status(200).json({ message: 'Request has been cancelled.' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

app.post('/api/requests/finalize', isAuthenticated, async (req, res) => {
    const { requestId, finalStatus } = req.body; // finalStatus should only be 'Closed' for successful fulfillment
    try {
        const request = await Request.findById(requestId);
        if (!request) return res.status(404).json({ message: 'Request not found.' });
        if (request.requestingHospital.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Not authorized.' });
        }
        
        // Only allow marking as 'Closed' (successfully fulfilled)
        if (finalStatus !== 'Closed') {
            return res.status(400).json({ message: 'Invalid status. Only successful fulfillment is allowed.' });
        }
        
        await Request.findByIdAndUpdate(requestId, { status: finalStatus });
        res.status(200).json({ message: 'Request has been marked as successfully fulfilled.' });
    } catch (error) {
        console.error("Finalize Error:", error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

// New endpoint for providers to reject requests
app.post('/api/requests/reject', isAuthenticated, async (req, res) => {
    const { requestId } = req.body;
    const providerHospitalId = req.session.userId;
    try {
        const request = await Request.findById(requestId);
        if (!request) return res.status(404).json({ message: 'Request not found.' });
        if (request.status !== 'Open') return res.status(400).json({ message: 'This request is no longer open.' });
        if (request.requestingHospital.toString() === providerHospitalId) {
            return res.status(400).json({ message: 'You cannot reject your own request.' });
        }
        
        // Simply mark as rejected - no inventory changes needed since it was never accepted
        await Request.findByIdAndUpdate(requestId, { 
            status: 'Rejected',
            providingHospital: providerHospitalId 
        });
        
        res.status(200).json({ message: 'Request has been rejected.' });
    } catch (error) {
        console.error("Reject Error:", error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

// --- KNOWLEDGE SHARING ROUTES ---
app.post('/api/knowledge', isAuthenticated, async (req, res) => {
    try {
        const { title, category, content } = req.body;
        const newArticle = new KnowledgeArticle({
            postingHospital: req.session.userId,
            title,
            category,
            content
        });
        await newArticle.save();
        res.status(201).json({ message: 'Knowledge article posted successfully!', article: newArticle });
    } catch (error) {
        console.error('Error posting knowledge article:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/knowledge', isAuthenticated, async (req, res) => {
    try {
        const articles = await KnowledgeArticle.find()
            .populate('postingHospital', 'hospitalName')
            .sort({ createdAt: -1 });
        res.json(articles);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// --- ADMIN ROUTES ---
app.get('/api/admin/hospitals', isAuthenticated, async (req, res) => {
    if (req.session.userType !== 'admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const hospitals = await Hospital.find().select('-password');
        res.json(hospitals);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/hospitals/:id', isAuthenticated, async (req, res) => {
    if (req.session.userType !== 'admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { id } = req.params;
        
        // Check if hospital exists
        const hospital = await Hospital.findById(id);
        if (!hospital) {
            return res.status(404).json({ message: 'Hospital not found.' });
        }
        
        // Delete all requests associated with this hospital
        await Request.deleteMany({
            $or: [
                { requestingHospital: id },
                { providingHospital: id }
            ]
        });
        
        // Delete the hospital
        await Hospital.findByIdAndDelete(id);
        
        res.status(200).json({ message: 'Hospital and associated data deleted successfully.' });
    } catch (error) {
        console.error('Delete hospital error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 8. SERVER LISTENER
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// DEFAULT ADMIN CREATION
const createDefaultAdmin = async () => {
    try {
        const adminExists = await Admin.findOne({ username: 'admin' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            const newAdmin = new Admin({ username: 'admin', password: hashedPassword });
            await newAdmin.save();
            console.log('Default admin created.');
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
};

createDefaultAdmin();