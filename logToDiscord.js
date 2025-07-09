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
const isProcessing = {
    booking: false,
    course: false,
    info: false,
    error: false,
    login: false,
    student: false,
    apicall: false
};

// ฟังก์ชั่นจัดการคิว webhook สำหรับแต่ละ URL
async function processQueue(urlType) {
    const url = getUrlByType(urlType);
    const queueForUrl = queue[urlType];

    while (queueForUrl.length > 0) {
        console.log(`⏳ Processing queue for ${urlType}: ${queueForUrl.length} items left`);
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
                logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + err.message, 'ไม่สามารถส่ง log student ไปยัง Discord ได้');
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
    //console.log("Adding message to queue:[" + urlType + "]\nMessage:" + message.description);
    queue[urlType].push(message);
    if (!isProcessing[urlType]) {
        isProcessing[urlType] = true;
        processQueue(urlType).finally(() => {
            isProcessing[urlType] = false;
        });
    }
}

// ฟังก์ชั่นส่ง log ไปที่ Discord ด้วย Embed
function logSystemToDiscord(type, title, message) {
    try {
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const safeTitle = String(title || '').slice(0, MAX_TITLE_LENGTH);
        const safeMessage = String(message || '').slice(0, MAX_DESCRIPTION_LENGTH);
        const embed = {
            title: safeTitle,
            description: safeMessage,
            color: type === 'error' ? 0xe74c3c : 0x2ecc71,
            timestamp: new Date().toISOString(),
            footer: {
                text: timestamp
            }
        };
        logToQueue(type, embed);
    } catch (error) {
        logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + error.message, 'ไม่สามารถส่ง log student ไปยัง Discord ได้');
        console.error('Error logging student to Discord:', error);
        throw error; // Re-throw the error after logging it
    }
}

function logLoginToDiscord(type, title, message) {
    try {
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const safeTitle = String(title || '').slice(0, MAX_TITLE_LENGTH);
        const safeMessage = String(message || '').slice(0, MAX_DESCRIPTION_LENGTH);
        const embed = {
            title: safeTitle,
            description: safeMessage,
            color: type === 'error' ? 0xe74c3c : 0x2ecc71,
            timestamp: new Date().toISOString(),
            footer: {
                text: timestamp
            }
        };
        if (type === 'error') {
            logToQueue(type, embed);
        } else {
            logToQueue('login', embed);
        }
    } catch (error) {
        logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + error.message, 'ไม่สามารถส่ง log student ไปยัง Discord ได้');
        console.error('Error logging student to Discord:', error);
        throw error; // Re-throw the error after logging it
    }
}
// ฟังก์ชั่นส่ง log การเปลี่ยนแปลงคอร์ส
function logCourseToDiscord(type, title, message, imageUrl = null) {
    try {
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const safeTitle = String(title || '').slice(0, MAX_TITLE_LENGTH);
        const safeMessage = String(message || '').slice(0, MAX_DESCRIPTION_LENGTH);
        const embed = {
            title: safeTitle,
            description: safeMessage,
            color: type === 'error' ? 0xe74c3c : 0x2ecc71,
            timestamp: new Date().toISOString(),
            footer: {
                text: timestamp
            }
        };

        if (imageUrl) { // ถ้ามี imageUrl ให้เพิ่ม object image เข้าไปใน embed
            embed.image = {
                url: imageUrl
            };
        }
        if (type === 'error') {
            logToQueue(type, embed);
        } else {
            logToQueue('course', embed);
        }
    } catch (error) {
        logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + error.message, 'ไม่สามารถส่ง log student ไปยัง Discord ได้');
        console.error('Error logging student to Discord:', error);
    }
}

// ฟังก์ชั่นส่งข้อความการจองไปยัง Discord channel
function logBookingToDiscord(type, title, message) {
    try {
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const safeTitle = String(title || '').slice(0, MAX_TITLE_LENGTH);
        const safeMessage = String(message || '').slice(0, MAX_DESCRIPTION_LENGTH);
        const embed = {
            title: safeTitle,
            description: safeMessage,
            color: type === 'error' ? 0xe74c3c : 0x2ecc71,
            timestamp: new Date().toISOString(),
            footer: {
                text: timestamp
            }
        };
        if (type === 'error') {
            logToQueue(type, embed);
        } else {
            logToQueue('booking', embed);
        }
    } catch (error) {
        logSystemToDiscord('error', '❌ เกิดข้อผิดพลาด : ' + error.message, 'ไม่สามารถส่ง log student ไปยัง Discord ได้');
        console.error('Error logging student to Discord:', error);
        throw error; // Re-throw the error after logging it
    }
}

function logStudentToDiscord(type, title, message) {
    try {
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const safeTitle = String(title || '').slice(0, MAX_TITLE_LENGTH);
        const safeMessage = String(message || '').slice(0, MAX_DESCRIPTION_LENGTH);

        const embed = {
            title: safeTitle,
            description: safeMessage,
            color: type === 'error' ? 0xe74c3c : 0x2ecc71,
            timestamp: new Date().toISOString(),
            footer: {
                text: timestamp
            }
        };
        if (type === 'error') {
            logToQueue(type, embed);
        } else {
            logToQueue('student', embed);
        }
    } catch (error) {
        // จัดการ error ที่อาจเกิดขึ้นภายใน logStudentToDiscord เอง
        const internalErrorMessage = error instanceof Error ? error.message : String(error);
        logSystemToDiscord('error', '❌ เกิดข้อผิดพลาดภายใน logStudentToDiscord: ' + internalErrorMessage, 'ไม่สามารถสร้าง embed สำหรับ log student ได้');
        console.error('Error in logStudentToDiscord itself:', error);
    }
}
module.exports = {
    logToQueue,
    logSystemToDiscord,
    logLoginToDiscord,
    logBookingToDiscord,
    logCourseToDiscord,
    logStudentToDiscord
};
