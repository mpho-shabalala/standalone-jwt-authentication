const fs = require('fs');

const fileHandler = {
  readData: (filePath) => {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (e) {
      return { users: [] };
    }
  },

  writeData: (filePath, data) => {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  }
};

module.exports = fileHandler;
