const axios = require('axios');
const DISCORD_INFO_WEBHOOK_URL = process.env.DISCORD_INFO_WEBHOOK_URL;
const DISCORD_ERROR_WEBHOOK_URL = process.env.DISCORD_ERROR_WEBHOOK_URL;
const DISCORD_WEBHOOK_URL_BOOKING = process.env.DISCORD_WEBHOOK_URL_BOOKING;
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
    error: []
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
    // เลือกคิวที่เกี่ยวข้อง
    const urlMap = {
        booking: DISCORD_WEBHOOK_URL_BOOKING,
        course: DISCORD_COURSE_WEBHOOK_URL,
        info: DISCORD_INFO_WEBHOOK_URL,
        error: DISCORD_ERROR_WEBHOOK_URL
    };

    // ตรวจสอบว่ามีข้อความในคิวหรือไม่
    while (queue[urlType].length > 0) {
        const message = queue[urlType].shift(); // ดึงข้อความออกจากคิว
        const url = urlMap[urlType];

        // ส่ง webhook
        let retryAfter = await sendWebhook(url, message);
        
        // ถ้ามีการ rate limit (error 429) ให้รอแล้วลองใหม่
        if (retryAfter) {
            console.log(`⏳ Retrying after ${retryAfter / 1000} seconds...`);
            await delay(retryAfter); // รอเวลาตามที่ Discord แนะนำ
        } else {
            // หน่วงเวลา 0.75 วินาที (750ms) ก่อนส่งข้อความถัดไป
            await delay(750);
        }
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
    const colorMap = {
        success: 0x2ecc71,
        info: 0x3498db,
        error: 0xe74c3c
    };

    const safeTitle = (title || '').slice(0, MAX_TITLE_LENGTH);
    const safeMessage = (message || '').slice(0, MAX_DESCRIPTION_LENGTH);
    const safeFooterText = 'Express.js Logger'.slice(0, MAX_FOOTER_LENGTH);

    const embed = {
        title: safeTitle,
        description: safeMessage,
        color: colorMap[type] || 0x95a5a6,
        timestamp: new Date().toISOString(),
        footer: {
            text: safeFooterText
        }
    };

    const SENDING_URL = type === 'error' ? DISCORD_ERROR_WEBHOOK_URL : DISCORD_INFO_WEBHOOK_URL;
    logToQueue(type, JSON.stringify({ embeds: [embed] }));
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
    logToQueue('course', JSON.stringify({ embeds: [embed] }));
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
