const axios = require('axios');
const DISCORD_INFO_WEBHOOK_URL = process.env.DISCORD_INFO_WEBHOOK_URL;
const DISCORD_ERROR_WEBHOOK_URL = process.env.DISCORD_ERROR_WEBHOOK_URL;
const DISCORD_BOOKING_WEBHOOK_URL = process.env.DISCORD_BOOKING_WEBHOOK_URL;
const DISCORD_COURSE_WEBHOOK_URL = process.env.DISCORD_COURSE_WEBHOOK_URL;

// ขนาดสูงสุดตามที่ Discord กำหนด
const MAX_TITLE_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_FOOTER_LENGTH = 2048;

// คิวสำหรับแต่ละ URL
const queue = {
    booking: [],
    course: [],
    info: [],
    error: [],
    success: []
};

// ตัวแปรสำหรับการตรวจสอบว่ากำลังประมวลผลคิวอยู่หรือไม่
let isProcessing = false;

// ฟังก์ชั่นหน่วงเวลา
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ฟังก์ชั่นส่ง webhook และ retry
async function sendWebhook(url, message) {
    try {
        await axios.post(url, { content: message });
    } catch (err) {
        if (err.response?.status === 429) {
            let retryAfter = 5 * 1000; // ค่าเริ่มต้น 5 วินาที
            const headerRetry = err.response.headers['retry-after'];
            const bodyRetry = err.response.data?.retry_after;

            if (headerRetry) {
                retryAfter = parseFloat(headerRetry) * 1000; // แปลงเป็นมิลลิวินาที
            } else if (bodyRetry) {
                retryAfter = parseFloat(bodyRetry);
            }

            console.warn(`⏳ Rate limited. Retrying in ${retryAfter / 1000} seconds...`);
            return retryAfter; // ส่งค่าการ retry
        } else {
            console.error("❌ Error sending to Discord:", err.response?.data || err.message);
        }
    }
}

// ฟังก์ชั่นจัดการคิว webhook สำหรับแต่ละ URL
async function processQueue(urlType) {
    const url = getUrlByType(urlType);
    const queueForUrl = queue[urlType];

    while (queueForUrl.length > 0) {
        const message = queueForUrl.shift();
        
        let payload;
        if (typeof message === 'string') {
            // กรณีเป็นข้อความธรรมดา
            payload = { content: message };
        } else if (message.embeds) {
            // ถ้ามี embeds อยู่แล้ว
            payload = message;
        } else {
            // กรณีเป็น embed เดี่ยว ๆ
            payload = { embeds: [message] };
        }

        try {
            await axios.post(url, payload);
        } catch (err) {
            if (err.response?.status === 429) {
                const retryAfter = err.response.headers['retry-after'] || 1;
                console.warn(`⏳ Rate limited. Retrying in ${retryAfter} seconds...`);
                await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
                queueForUrl.unshift(message); // ใส่กลับไปในคิว
            } else {
                console.error("❌ Error sending to Discord:", err);
            }
        }

        // รอ 0.75 วินาที
        await new Promise((resolve) => setTimeout(resolve, 750));
    }
}

// ฟังก์ชั่นเพื่อให้ URL ตามประเภท
function getUrlByType(urlType) {
    switch (urlType) {
        case 'info':
            return DISCORD_INFO_WEBHOOK_URL;
        case 'error':
            return DISCORD_ERROR_WEBHOOK_URL;
        case 'booking':
            return DISCORD_BOOKING_WEBHOOK_URL;
        case 'course':
            return DISCORD_COURSE_WEBHOOK_URL;
        case 'success':
            return DISCORD_INFO_WEBHOOK_URL;
        default:
            throw new Error(`Unknown URL type: ${urlType}`);
    }
}

// ฟังก์ชั่นสำหรับเพิ่มข้อความลงในคิวและเริ่มประมวลผล
function logToQueue(urlType, message) {
    queue[urlType].push(message);
    if (!isProcessing) {
        isProcessing = true;
        processQueue(urlType).finally(() => {
            isProcessing = false;
        });
    }
}

// ฟังก์ชั่นส่ง log ไปที่ Discord ด้วย Embed
function logSystemToDiscord(type, title, message) {
    const embed = {
        title: title || '',
        description: message || '',
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: 'Express.js Logger'
        }
    };

    logToQueue(type === 'error' ? 'error' : 'info', embed);
}

// ฟังก์ชั่นส่ง log การเปลี่ยนแปลงคอร์ส
function logCourseToDiscord(title, message) {
    const embed = {
        title: title.slice(0, MAX_TITLE_LENGTH),
        description: message.slice(0, MAX_DESCRIPTION_LENGTH),
        color: 0x3498db,
        timestamp: new Date().toISOString(),
        footer: {
            text: 'Express.js Logger'
        }
    };
    logToQueue('course', embed);
}

// ฟังก์ชั่นส่งข้อความการจองไปยัง Discord channel
function logBookingToDiscord(message) {
    logToQueue('booking', message);
}

// ฟังก์ชันแจ้งเตือนเมื่อมีการจอง
async function sendNotification(jsonData) {
    try {
        logBookingToDiscord(jsonData.message);
        console.log('📢 Notification Sent Successfully');
    } catch (error) {
        console.error('❌ Error sending notification:', error.stack);
        throw error;
    }
}

// ฟังก์ชันแจ้งเตือนเมื่อมีการอัปเดตการจอง
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
