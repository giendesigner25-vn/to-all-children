// ADMIN PAGES - FIXED FILE PATHS

function sendAdminPage(filename, res) {
  const possiblePaths = [
    path.join(__dirname, filename),
    path.join(__dirname, '..', filename),
    path.join(__dirname, 'public', filename),
    path.join(__dirname, '..', 'public', filename)
  ];

  const filePath = possiblePaths.find(candidate => {
    return fs.existsSync(candidate) &&
      fs.statSync(candidate).isFile();
  });

  if (!filePath) {
    console.error('ADMIN PAGE NOT FOUND:', filename);
    console.error('Checked paths:', possiblePaths);

    return res.status(404).send(
      `Page not found: ${filename}`
    );
  }

  return res.sendFile(filePath);
}

// Admin login page
app.get('/admin.html', (req, res) => {
  sendAdminPage('admin.html', res);
});

// Admin dashboard
app.get('/admin-dashboard.html', (req, res) => {
  sendAdminPage('admin-dashboard.html', res);
});

// Old dashboard URL compatibility
app.get('/admin-dashboar.html', (req, res) => {
  sendAdminPage('admin-dashboard.html', res);
});
