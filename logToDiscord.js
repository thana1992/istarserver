const axios = require('axios');
const e = require('express');
const { info } = require('winston');
const DISCORD_INFO_WEBHOOK_URL = process.env.DISCORD_INFO_WEBHOOK_URL;
const DISCORD_ERROR_WEBHOOK_URL = process.env.DISCORD_ERROR_WEBHOOK_URL;
const DISCORD_WEBHOOK_URL_BOOKING = process.env.DISCORD_WEBHOOK_URL_BOOKING;
const DISCORD_COURSE_WEBHOOK_URL = process.env.DISCORD_COURSE_WEBHOOK_URL;

// ขนาดสูงสุดตามที่ Discord กำหนด
const MAX_TITLE_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_FOOTER_LENGTH = 2048;
/**
 * ส่ง log ไปที่ Discord ด้วย Embed
 * @param {'success'|'error'} type ประเภท log
 * @param {string} title หัวเรื่อง
 * @param {string} message เนื้อหา
 */
function logSystemToDiscord(type, title, message) {
    const colorMap = {
        success: 0x2ecc71,
        info: 0x3498db,
        error: 0xe74c3c
    };

    // ตัดข้อความหากเกินขนาด
    const safeTitle = title.length > MAX_TITLE_LENGTH ? title.slice(0, MAX_TITLE_LENGTH - 3) + '...' : title;
    const safeDescription = message.length > MAX_DESCRIPTION_LENGTH ? message.slice(0, MAX_DESCRIPTION_LENGTH - 3) + '...' : message;
    const safeFooterText = 'Express.js Logger'.length > MAX_FOOTER_LENGTH
        ? 'Express.js Logger'.slice(0, MAX_FOOTER_LENGTH - 3) + '...'
        : 'Express.js Logger';

    const embed = {
        title: safeTitle,
        description: safeDescription,
        color: colorMap[type] || 0x95a5a6,
        timestamp: new Date().toISOString(),
        footer: {
            text: safeFooterText
        }
    };

    const SENDING_URL = type === 'error' ? DISCORD_ERROR_WEBHOOK_URL : DISCORD_INFO_WEBHOOK_URL;

    const sendToDiscord = async () => {
        try {
            await axios.post(SENDING_URL, {
                embeds: [embed]
            });
        } catch (err) {
            if (err.response?.status === 429) {
                const retryAfter = err.response.headers['retry-after'] || 5;
                console.error(`⏳ Rate limited by Discord. Retrying in ${retryAfter} seconds...`);
                setTimeout(sendToDiscord, retryAfter * 1000);
            } else if (err.response?.status === 400) {
                console.error("⚠️ Error 400 Bad Request. Possibly due to message too long.");
                console.error("📦 Embed causing issue:", JSON.stringify(embed, null, 2));
                console.error("🛑 Discord response:", err.response.data);
            } else {
                console.error("❌ Error sending to Discord:", err);
            }
        }
    };

    sendToDiscord();
}

/**
 * ส่ง log การเปลี่ยนแปลงคอร์ส
 * @param {string} title หัวข้อ
 * @param {string} message เนื้อหา
 */
function logCourseToDiscord(title, message) {
    const safeTitle = title.length > MAX_TITLE_LENGTH ? title.slice(0, MAX_TITLE_LENGTH - 3) + '...' : title;
    const safeDescription = message.length > MAX_DESCRIPTION_LENGTH ? message.slice(0, MAX_DESCRIPTION_LENGTH - 3) + '...' : message;

    const embed = {
        title: safeTitle,
        description: safeDescription,
        color: 0x3498db,
        timestamp: new Date().toISOString(),
        footer: {
            text: 'Express.js Logger'
        }
    };

    axios.post(DISCORD_COURSE_WEBHOOK_URL, {
        embeds: [embed]
    }).catch((err) => {
        if (err.response?.status === 429) {
            console.warn("⏳ Rate limited by Discord. Skipping...");
        } else {
            console.error("❌ Error sending course log to Discord:", err);
        }
    });
}

/**
 * ส่งข้อความการจองไปยัง Discord channel
 * @param {string} message 
 */
function logBookingToDiscord(message) {
    axios.post(DISCORD_WEBHOOK_URL_BOOKING, {
        content: message,
    }).catch((err) => {
        if (err.response?.status === 429) {
            console.warn("⏳ Rate limited by Discord. Skipping...");
        } else {
            console.error("❌ Error sending booking to Discord:", err);
        }
    });
}

/**
 * ฟังก์ชันแจ้งเตือนเมื่อมีการจอง
 * @param {{ message: string }} jsonData 
 */
async function sendNotification(jsonData) {
    try {
        logBookingToDiscord(jsonData.message);
        console.log('📢 Notification Sent Successfully');
    } catch (error) {
        console.error('❌ Error sending notification:', error.stack);
        throw error;
    }
}

/**
 * ฟังก์ชันแจ้งเตือนเมื่อมีการอัปเดตการจอง
 * @param {{ message: string }} jsonData 
 */
async function sendNotificationUpdate(jsonData) {
    try {
        logBookingToDiscord(jsonData.message);
        console.log('📢 Notification Sent Successfully');
    } catch (error) {
        console.error('❌ Error sending update notification:', error.stack);
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

