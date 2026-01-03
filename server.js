const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();
const PORT = process. env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Directories
const PAYMENT_LOG_DIR = path.join(__dirname, 'logs', 'payments');
const BOT_FILES_DIR = path. join(__dirname, 'bot-files');
const LICENSE_DIR = path.join(__dirname, 'licenses');

// Create directories
[PAYMENT_LOG_DIR, BOT_FILES_DIR, LICENSE_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Email Setup
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env. EMAIL_USER,
    pass:  process.env.EMAIL_PASSWORD
  }
});

// PayPal Config
const PAYPAL_API = process.env.PAYPAL_API_URL || 'https://api.sandbox.paypal.com';
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process. env.PAYPAL_SECRET;

// ========== LOGGING FUNCTION ==========
function logPayment(data) {
  const timestamp = new Date().toISOString();
  const dateStr = timestamp.split('T')[0];
  const logFile = path.join(PAYMENT_LOG_DIR, `payments-${dateStr}.log`);
  
  const logEntry = {
    timestamp,
    transactionId: crypto.randomUUID().substring(0, 16),
    ...data,
    emailHash: crypto.createHash('sha256').update(data.email).digest('hex').substring(0, 12)
  };

  delete logEntry.email;
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
  console.log(`✅ Payment logged: ${logEntry.transactionId}`);
  
  return logEntry;
}

// ========== LICENSE GENERATION ==========
function generateLicense(email, licenseType = 'STANDARD') {
  const timestamp = Date.now();
  const random = crypto.randomBytes(8).toString('hex');
  const encoded = Buffer.from(`${email}: ${timestamp}`).toString('base64');
  const licenseKey = `ASE-${encoded. substring(0, 20).toUpperCase()}-${random. substring(0, 8).toUpperCase()}`;
  
  const issuedDate = new Date();
  let expiryDate, tradingAccounts, features;

  switch(licenseType. toUpperCase()) {
    case 'BASIC':
      expiryDate = new Date(issuedDate.getTime() + 30 * 24 * 60 * 60 * 1000);
      tradingAccounts = 1;
      features = ['BasicPatterns', 'Dashboard'];
      break;
    case 'STANDARD':
      expiryDate = new Date(issuedDate.getTime() + 365 * 24 * 60 * 60 * 1000);
      tradingAccounts = 2;
      features = ['AllPatterns', 'AdaptiveLearning', 'DynamicSL', 'PositionScaling'];
      break;
    case 'PROFESSIONAL':
      expiryDate = new Date(issuedDate. getTime() + 730 * 24 * 60 * 60 * 1000);
      tradingAccounts = 5;
      features = ['AllPatterns', 'AdaptiveLearning', 'DynamicSL', 'AdvancedAnalytics', 'PrioritySupport'];
      break;
    case 'LIFETIME': 
      expiryDate = new Date(2099, 12, 31);
      tradingAccounts = 10;
      features = ['AllPatterns', 'AdaptiveLearning', 'DynamicSL', 'AdvancedAnalytics', 'PrioritySupport', 'FreeUpdates'];
      break;
    default:
      licenseType = 'STANDARD';
      expiryDate = new Date(issuedDate.getTime() + 365 * 24 * 60 * 60 * 1000);
      tradingAccounts = 2;
      features = ['AllPatterns', 'AdaptiveLearning', 'DynamicSL'];
  }

  const license = {
    licenseKey,
    email,
    type: licenseType,
    issuedDate:  issuedDate.toISOString(),
    expiryDate: expiryDate.toISOString(),
    status: 'ACTIVE',
    tradingAccounts,
    features,
    createdAt: new Date().toISOString()
  };

  const licenseFile = path.join(LICENSE_DIR, `${email}. json`);
  fs.writeFileSync(licenseFile, JSON.stringify(license, null, 2));

  return license;
}

// ========== PAYPAL FUNCTIONS ==========
async function getPayPalAccessToken() {
  try {
    const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString('base64');
    
    const response = await axios.post(
      `${PAYPAL_API}/v1/oauth2/token`,
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    return response. data.access_token;
  } catch (error) {
    console.error('❌ PayPal Token Error:', error.message);
    throw error;
  }
}

async function createPayPalOrder(amount, email) {
  try {
    const accessToken = await getPayPalAccessToken();

    const response = await axios.post(
      `${PAYPAL_API}/v2/checkout/orders`,
      {
        intent: 'CAPTURE',
        purchase_units: [{
          amount:  {
            currency_code: 'USD',
            value: amount. toString()
          },
          description: `Adaptive Swing EA Bot License - ${email}`
        }]
      },
      {
        headers: {
          'Authorization':  `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error) {
    console.error('❌ PayPal Order Error:', error.message);
    throw error;
  }
}

async function capturePayPalOrder(orderId) {
  try {
    const accessToken = await getPayPalAccessToken();

    const response = await axios.post(
      `${PAYPAL_API}/v2/checkout/orders/${orderId}/capture`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error) {
    console.error('❌ PayPal Capture Error:', error.message);
    throw error;
  }
}

// ========== EMAIL SENDING ==========
async function sendBotDownloadEmail(email, licenseKey, licenseType) {
  const downloadLink = `${process.env.FRONTEND_URL}/download? key=${licenseKey}&email=${email}`;

  const mailOptions = {
    from:  process.env.EMAIL_USER,
    to: email,
    subject: '✅ Your Adaptive Swing EA Bot is Ready!',
    html: `
      <div style="font-family: Arial; background:  linear-gradient(135deg, #0f0c29, #302b63); padding: 40px; border-radius: 10px; color: white; max-width: 600px;">
        <h2 style="color: #00ff88;">🎉 Payment Successful!</h2>
        <p>Thank you for purchasing Adaptive Swing EA Trading Bot (${licenseType}).</p>
        
        <div style="background: rgba(0, 255, 136, 0.1); padding: 20px; border-radius:  8px; border-left: 4px solid #00ff88; margin:  20px 0;">
          <p><strong>📥 Download Your Bot:  </strong></p>
          <a href="${downloadLink}" style="display: inline-block; background: linear-gradient(135deg, #00ff88, #00d4ff); color: #0f0c29; padding: 15px 40px; border-radius: 25px; text-decoration: none; font-weight: bold;">
            ⬇️ Download AdaptiveSwingEA.ex4
          </a>
          <p style="margin-top: 15px; font-size: 12px;">License Key: <code>${licenseKey}</code></p>
        </div>

        <div style="background: rgba(255, 255, 255, 0.05); padding: 15px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: #00ff88;">🚀 Quick Start:</h3>
          <ol style="color: #a8b2d1;">
            <li>Save the . ex4 file to:  <code>MQL5/Experts/</code></li>
            <li>Restart MT5 terminal</li>
            <li>Paste license key in EA settings:  <code>${licenseKey}</code></li>
            <li>Start trading!  💰</li>
          </ol>
        </div>

        <div style="background: rgba(255, 255, 255, 0.05); padding: 15px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: #00ff88;">📞 Support:</h3>
          <p style="color: #a8b2d1;">
            📱 WhatsApp: <a href="https://wa.me/254799071779" style="color: #00ff88;">+254 799 071 779</a><br>
            📸 Instagram: <a href="https://instagram.com/HUNTER_MATO. FX" style="color: #00ff88;">@HUNTER_MATO.FX</a>
          </p>
        </div>

        <p style="color: #667eea; margin-top: 30px; font-size: 12px;">
          ⚠️ Trading involves risk. Past performance doesn't guarantee future results. 
        </p>
      </div>
    `
  };

  return new Promise((resolve, reject) => {
    emailTransporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('❌ Email Error:', error);
        reject(error);
      } else {
        console. log('✅ Email sent to:', email);
        resolve(info);
      }
    });
  });
}

// ========== API ROUTES ==========

// 1. Create Payment Order
app.post('/api/payments/create-order', async (req, res) => {
  try {
    const { email, amount = 100, licenseType = 'STANDARD' } = req.body;

    if (!email || !email.includes('@')) {
      return res. status(400).json({ success: false, message: 'Valid email required' });
    }

    logPayment({
      email,
      amount,
      licenseType,
      status: 'INITIATED',
      action: 'CREATE_ORDER'
    });

    const order = await createPayPalOrder(amount, email);

    res.json({
      success: true,
      orderId:  order.id,
      approveUrl: order.links.find(l => l.rel === 'approve').href
    });
  } catch (error) {
    logPayment({
      email:  req.body.email,
      status: 'ERROR',
      action: 'CREATE_ORDER_FAILED',
      error: error. message
    });
    res.status(500).json({ success: false, message: error.message });
  }
});

// 2. Capture Payment & Issue License
app.post('/api/payments/capture-order', async (req, res) => {
  try {
    const { orderId, email, licenseType = 'STANDARD' } = req.body;

    if (! orderId || !email) {
      return res.status(400).json({ success: false, message: 'OrderID and email required' });
    }

    const capture = await capturePayPalOrder(orderId);

    if (capture.status === 'COMPLETED') {
      const amount = capture.purchase_units[0].amount.value;
      
      // Generate License
      const license = generateLicense(email, licenseType);

      logPayment({
        email,
        amount,
        licenseType,
        status: 'COMPLETED',
        action: 'PAYMENT_CAPTURED',
        orderId,
        licenseKey: license.licenseKey
      });

      // Send Email
      try {
        await sendBotDownloadEmail(email, license.licenseKey, licenseType);
      } catch (emailError) {
        console.error('Email Error:', emailError);
      }

      res.json({
        success: true,
        message: 'Payment successful!  Check your email for download link.',
        licenseKey: license.licenseKey,
        expiryDate: license.expiryDate
      });
    } else {
      logPayment({
        email,
        status: 'FAILED',
        action: 'PAYMENT_CAPTURE_FAILED',
        orderId,
        paypalStatus: capture.status
      });

      res.status(400).json({ success: false, message: `Payment failed: ${capture.status}` });
    }
  } catch (error) {
    logPayment({
      email: req.body.email,
      status: 'ERROR',
      action: 'PAYMENT_CAPTURE_ERROR',
      error: error.message
    });

    res.status(500).json({ success: false, message: error.message });
  }
});

// 3. Download Bot File
app.get('/api/bot-files/download', (req, res) => {
  try {
    const { key, email } = req.query;

    if (!key || !email) {
      return res.status(400).json({ success: false, message: 'License key and email required' });
    }

    const licenseFile = path.join(LICENSE_DIR, `${email}.json`);
    
    if (!fs. existsSync(licenseFile)) {
      logPayment({ email, status: 'DOWNLOAD_FAILED', action: 'INVALID_LICENSE' });
      return res.status(403).json({ success: false, message: 'Invalid license' });
    }

    const license = JSON.parse(fs.readFileSync(licenseFile, 'utf8'));

    if (license.licenseKey !== key || license.status !== 'ACTIVE') {
      logPayment({ email, status: 'DOWNLOAD_FAILED', action: 'INVALID_LICENSE_KEY' });
      return res.status(403).json({ success: false, message: 'License key invalid' });
    }

    if (new Date(license.expiryDate) < new Date()) {
      logPayment({ email, status: 'DOWNLOAD_FAILED', action:  'LICENSE_EXPIRED' });
      return res.status(403).json({ success: false, message: 'License expired' });
    }

    logPayment({ email, status: 'FILE_DOWNLOADED', action: 'BOT_DOWNLOAD', licenseKey: key });

    const botFile = path.join(BOT_FILES_DIR, 'AdaptiveSwingEA.ex4');
    
    if (!fs.existsSync(botFile)) {
      return res.status(404).json({ success: false, message: 'Bot file not found' });
    }

    res.download(botFile, 'AdaptiveSwingEA.ex4');
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 4. Get License Info
app.get('/api/licenses/: email', (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const licenseFile = path.join(LICENSE_DIR, `${email}.json`);

    if (!fs.existsSync(licenseFile)) {
      return res.status(404).json({ exists: false, message: 'No license found' });
    }

    const license = JSON.parse(fs.readFileSync(licenseFile, 'utf8'));
    const expiryDate = new Date(license.expiryDate);
    const daysRemaining = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

    res.json({
      exists: true,
      license,
      daysRemaining:  daysRemaining > 0 ? daysRemaining : 0,
      isExpired: expiryDate < new Date()
    });
  } catch (error) {
    res.status(500).json({ exists: false, message: error.message });
  }
});

// 5. Admin Payment Logs
app.get('/api/admin/payment-logs', (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    
    if (adminKey !== process.env. ADMIN_KEY) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const today = new Date().toISOString().split('T')[0];
    const logFile = path.join(PAYMENT_LOG_DIR, `payments-${today}.log`);

    if (!fs.existsSync(logFile)) {
      return res.json({ success: true, logs: [], stats: { total: 0, completed: 0, revenue: 0 } });
    }

    const logs = fs. readFileSync(logFile, 'utf8')
      .split('\n')
      .filter(line => line. trim())
      .map(line => JSON.parse(line))
      .reverse();

    const completed = logs.filter(l => l.status === 'COMPLETED').length;
    const revenue = logs.filter(l => l.status === 'COMPLETED').reduce((sum, l) => sum + (l.amount || 0), 0);

    res.json({
      success: true,
      stats: { total: logs.length, completed, revenue },
      logs
    });
  } catch (error) {
    res.status(500).json({ success: false, message:  error.message });
  }
});

// 6. Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'running', timestamp: new Date().toISOString() });
});

// 7. Home Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  🚀 Adaptive Swing EA Payment Server Started            ║');
  console.log(`║  Port: ${PORT}                                              ║`);
  console.log(`║  Mode: ${process.env.NODE_ENV}                                        ║`);
  console.log('╚════════════════════════════════════════════════════════╝\n');
});
