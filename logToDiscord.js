const axios = require('axios');
const e = require('express');
const { info } = require('winston');
const DISCORD_INFO_WEBHOOK_URL = process.env.DISCORD_INFO_WEBHOOK_URL;
const DISCORD_ERROR_WEBHOOK_URL = process.env.DISCORD_ERROR_WEBHOOK_URL;
const DISCORD_WEBHOOK_URL_BOOKING = process.env.DISCORD_WEBHOOK_URL_BOOKING;
const DISCORD_COURSE_WEBHOOK_URL = process.env.DISCORD_COURSE_WEBHOOK_URL;

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
        },
    };

    var SENDING_URL = DISCORD_INFO_WEBHOOK_URL;
    if (type === 'error') {
        SENDING_URL = DISCORD_ERROR_WEBHOOK_URL;
    }

    axios.post(SENDING_URL, {
        embeds: [embed]
    }).catch((err) => {
        if (err.response?.status === 429) {
            console.warn("⏳ Rate limited by Discord. Skipping...");
        } else if (err.response?.status === 400) {
            console.warn("⚠️ Invalid webhook URL. Please check your configuration. [URL] ", SENDING_URL);
        } else {
            console.error("❌ Error sending to Discord:", err);
        }
    });
}

function logCourseToDiscord(message) {
    const embed = {
        title,
        description: message,
        color: 0x3498db,
        timestamp: new Date().toISOString(),
        footer: {
            text: 'Express.js Logger'
        },
    };
    axios.post(DISCORD_COURSE_WEBHOOK_URL, {
        embeds: [embed]
    }).catch((err) => {
        if (err.response?.status === 429) {
            console.warn("⏳ Rate limited by Discord. Skipping...");
        } else {
            console.error("❌ Error sending to Discord:", err);
        }
    });
}
function logBookingToDiscord(message) {
    axios.post(DISCORD_WEBHOOK_URL_BOOKING, {
      content: message,
    }).catch((err) => {
        if (err.response?.status === 429) {
            console.warn("⏳ Rate limited by Discord. Skipping...");
        } else {
            console.error("❌ Error sending to Discord:", err);
        }
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
    sendNotificationUpdate,
    logCourseToDiscord
};

