const QRCode = require('qrcode');

const base = { errorCorrectionLevel: 'M' };

module.exports = {
  terminal: (text) => QRCode.toString(text, { ...base, type: 'terminal', small: true, margin: 2 }),
  png: (text, width = 1024) => QRCode.toBuffer(text, { ...base, type: 'png', margin: 3, width }),
};
