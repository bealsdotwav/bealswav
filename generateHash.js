const bcrypt = require('bcrypt');

const password = 'mySecurePassword123';
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    return console.error("Error generating hash:", err);
  }
  console.log("New bcrypt hash:", hash);
});
