// Remembers choices between runs so the local link (name + port) stays the same.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { randomWords } = require('./words');

const FILE = path.join(__dirname, '..', 'share-settings.json');
const OLD_KEYS = ['lanName', 'lanKey', 'lanLock', 'dashboardPort'];

const randomPin = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

const DEFAULTS = {
  targetPort: 7860,
  lanPort: 8000,
  lanPin: true, // the local link asks for the PIN too unless you turn it off
};

function load() {
  let saved = {};
  try { saved = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { /* first run */ }
  const settings = { ...DEFAULTS, ...saved };
  for (const key of OLD_KEYS) delete settings[key];
  if (!settings.lanWords || !/^[a-z]+(-[a-z]+)+$/.test(settings.lanWords)) settings.lanWords = randomWords(3);
  if (!settings.lanSecret) settings.lanSecret = crypto.randomBytes(32).toString('base64url');
  if (!settings.lanPorts || typeof settings.lanPorts !== 'object') settings.lanPorts = {}; // app port -> local link port
  if (!/^\d{4,12}$/.test(String(settings.pin || ''))) settings.pin = randomPin();
  return settings;
}

function save(settings) {
  try {
    fs.writeFileSync(FILE, JSON.stringify(settings, null, 2));
  } catch (err) {
    console.error(`Could not save settings: ${err.message}`);
  }
}

module.exports = { load, save, randomPin, FILE };
