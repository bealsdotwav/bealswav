const bcrypt = require('bcrypt');

// Replace this with your test password.
const plainPassword = "mySecurePassword123";

// Replace this hash with the one from your users.json file.
const hashFromFile = "$2b$10$w3jPCmR0nR7zL5o8r2ZqAu7XNCkZ0w3hZv.m3Qyfk64efZdREp7hm";

bcrypt.compare(plainPassword, hashFromFile)
  .then(result => {
    console.log("Password valid?", result);
  })
  .catch(err => console.error("Error comparing password:", err));
