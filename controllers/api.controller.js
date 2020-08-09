const validator = require('validator');
const { promisify } = require('util');
var lusca = require('lusca');
/**
 * GET /api
 * List of API examples.
 */
exports.getApi = (req, res) => {
  res.render('api/index', {
    title: 'API Examples'
  });
};

/**
 * GET /api/upload
 * File Upload API example.
 */

exports.getFileUpload = (req, res) => {
  res.render('api/upload.ejs', {
    title: 'File Upload'
  });
};

exports.postFileUpload = (req, res) => {
  req.flash('success', { msg: 'File was uploaded successfully.' });
  res.redirect('/api/upload');
};


/**
 * GET /api/maps
 * Create maps
 */
exports.getHereMaps = (req, res) => {
  const imageMapURL = `https://image.maps.api.here.com/mia/1.6/mapview?\
app_id=${process.env.HERE_APP_ID}&app_code=${process.env.HERE_APP_CODE}&\
poix0=47.6516216,-122.3498897;white;black;15;Fremont Troll&\
poix1=47.6123335,-122.3314332;white;black;15;Seattle Art Museum&\
poix2=47.6162956,-122.3555097;white;black;15;Olympic Sculpture Park&\
poix3=47.6205099,-122.3514661;white;black;15;Space Needle&\
c=47.6176371,-122.3344637&\
u=1500&\
vt=1&&z=13&\
h=500&w=800&`;

  res.render('api/maps', {
    app_id: process.env.HERE_APP_ID,
    app_code: process.env.HERE_APP_CODE,
    title: 'Here Maps API',
    imageMapURL
  });
};