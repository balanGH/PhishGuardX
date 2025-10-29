const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { Parser } = require('json2csv');

const app = express();
const PORT = 5000;

app.use(bodyParser.json());

app.post('/analyze', (req, res) => {
  const { url, features } = req.body;
  if (!url || !features) {
    return res.status(400).json({ error: 'Missing url or features' });
  }

  // Flatten features and add url
  const row = { url, ...features };

  // Convert to CSV
  const csvFields = Object.keys(row);
  const parser = new Parser({ fields: csvFields, header: !fs.existsSync('output.csv') });
  let csv;
  try {
    csv = parser.parse([row]);
  } catch (err) {
    return res.status(500).json({ error: 'CSV parse error' });
  }

  // Append to file
  fs.appendFile('output.csv', csv + '\n', (err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to save CSV' });
    }
    res.json({ status: 'success', saved: row });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});