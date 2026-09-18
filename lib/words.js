// Random easy-to-read names like "amber-otter-river" for the local network link.
const crypto = require('crypto');

const WORDS = `
acorn amber anchor apple arrow aspen autumn bamboo basil beacon berry birch bison blossom breeze brook
cactus candle canyon cedar cherry cider clover cobalt comet coral cotton crane crystal daisy delta dune
eagle echo ember falcon fern fig finch flame forest fossil fox frost galaxy garden gecko ginger glacier
granite grape harbor hazel heron honey horizon husky iris island ivory jade jasmine jungle juniper kayak
kite koala lagoon lake lark lava lemon lilac lily lime linen lotus lunar magnet mango maple marble meadow
melon mint mist moss nectar nova oak oasis ocean olive onyx opal orchid otter owl palm panda pearl pebble
pepper pine planet plum polar pony poppy prairie puffin quartz quill rain raven reef ripple river robin
ruby saffron sage sail salmon sand sapphire shore silk silver sky snow sparrow spice spruce star stone
storm summit sun swan tango thunder tiger topaz tulip tundra valley velvet violet walnut wave willow wind
wolf zebra zen
`.trim().split(/\s+/);

function randomWords(count = 3) {
  return Array.from({ length: count }, () => WORDS[crypto.randomInt(WORDS.length)]).join('-');
}

module.exports = { randomWords };
