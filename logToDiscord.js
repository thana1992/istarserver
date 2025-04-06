const axios = require('axios');
const DISCORD_INFO_WEBHOOK_URL = process.env.DISCORD_INFO_WEBHOOK_URL;
const DISCORD_ERROR_WEBHOOK_URL = process.env.DISCORD_ERROR_WEBHOOK_URL;
const DISCORD_BOOKING_WEBHOOK_URL = process.env.DISCORD_BOOKING_WEBHOOK_URL;
const DISCORD_COURSE_WEBHOOK_URL = process.env.DISCORD_COURSE_WEBHOOK_URL;
const DISCORD_LOGIN_WEBHOOK_URL = process.env.DISCORD_LOGIN_WEBHOOK_URL;
const DISCORD_STUDENT_WEBHOOK_URL = process.env.DISCORD_STUDENT_WEBHOOK_URL;
const DISCORD_APICALL_WEBHOOK_URL = process.env.DISCORD_APICALL_WEBHOOK_URL;
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
    login: [],
    student: [],
    apicall: []
};

// ตัวแปรสำหรับการตรวจสอบว่ากำลังประมวลผลคิวอยู่หรือไม่
let isProcessing = false;

// ฟังก์ชั่นจัดการคิว webhook สำหรับแต่ละ URL
async function processQueue(urlType) {s
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
        case 'login':
            return DISCORD_LOGIN_WEBHOOK_URL;
        case 'student':
            return DISCORD_STUDENT_WEBHOOK_URL;
        case 'apicall':
            return DISCORD_APICALL_WEBHOOK_URL;
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
    const timestamp = new Date().toISOString();
    const embed = {
        title: title || '',
        description: message || '',
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: timestamp
        }
    };

    logToQueue('info', embed);
}

function logLoginToDiscord(type, title, message) {
    const timestamp = new Date().toISOString();
    const embed = {
        title: title.slice(0, MAX_TITLE_LENGTH),
        description: message.slice(0, MAX_DESCRIPTION_LENGTH),
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: timestamp
        }
    };
    logToQueue('login', embed);
}
// ฟังก์ชั่นส่ง log การเปลี่ยนแปลงคอร์ส
function logCourseToDiscord(type, title, message) {
    const timestamp = new Date().toISOString();
    const embed = {
        title: title.slice(0, MAX_TITLE_LENGTH),
        description: message.slice(0, MAX_DESCRIPTION_LENGTH),
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: timestamp
        }
    };
    logToQueue('course', embed);
}

// ฟังก์ชั่นส่งข้อความการจองไปยัง Discord channel
function logBookingToDiscord(type, title, message) {
    const timestamp = new Date().toISOString();
    const embed = {
        title: title.slice(0, MAX_TITLE_LENGTH),
        description: message.slice(0, MAX_DESCRIPTION_LENGTH),
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: timestamp
        }
    };
    logToQueue('booking', embed);
}

function logStudentToDiscord(title, message) {
    const timestamp = new Date().toISOString();
    const embed = {
        title: title.slice(0, MAX_TITLE_LENGTH),
        description: message.slice(0, MAX_DESCRIPTION_LENGTH),
        color: type === 'error' ? 0xe74c3c : 0x2ecc71,
        timestamp: new Date().toISOString(),
        footer: {
            text: timestamp
        }
    };
    logToQueue('student', embed);
}

module.exports = {
    logToQueue,
    logSystemToDiscord,
    logLoginToDiscord,
    logBookingToDiscord,
    logCourseToDiscord,
    logStudentToDiscord
};
