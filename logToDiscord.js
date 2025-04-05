const axios = require('axios');
const { info } = require('winston');
const DISCORD_WEBHOOK_URL_SYSTEM = process.env.DISCORD_WEBHOOK_URL_SYSTEM;
const DISCORD_WEBHOOK_URL_BOOKING = process.env.DISCORD_WEBHOOK_URL_BOOKING;

/**
 * ส่ง log ไปที่ Discord ด้วย Embed สวยงาม
 * @param {'success'|'error'} type ประเภท log
 * @param {string} title หัวเรื่อง
 * @param {string} message เนื้อหา
 */

function logSystemToDiscord(type, title, message) {
  const colorMap = {
    success: 0x2ecc71, // เขียว
    info: 0x3498db,   // น้ำเงิน
    error: 0xe74c3c    // แดง
  };

  const embed = {
    title,
    description: message,
    color: colorMap[type] || 0x95a5a6, // เทาเป็นค่า default
    timestamp: new Date().toISOString(),
    footer: {
      text: 'Express.js Logger'
    }
  };

  axios.post(DISCORD_WEBHOOK_URL_SYSTEM, {
    embeds: [embed]
  }).catch((err) => {
    console.error('❌ ไม่สามารถส่ง log ไปที่ Discord:', err.message);
  });
}

function logBookingToDiscord(message) {
    axios.post(DISCORD_WEBHOOK_URL_BOOKING, {
      content: message,
    }).catch((err) => {
      console.error('Error sending log to Discord:', err.message);
    });
}
async function sendNotification(jsonData) {
    try {
    // Send notification
    logBookingToDiscord(jsonData.message);
    console.log('Notification Sent Successfully');
    } catch (error) {
    console.error('Error sending notification', error.stack);
    throw error;
    }
}
async function sendNotificationUpdate(jsonData) {
    try {
    // Send notification
    logBookingToDiscord(jsonData.message);
    console.log('Notification Sent Successfully');
    } catch (error) {
    console.error('Error sending notification:', error.stack);
    throw error;
    }
}

module.exports = {
    logSystemToDiscord,
    logBookingToDiscord,
    sendNotification,
    sendNotificationUpdate
};

