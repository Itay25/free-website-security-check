document.getElementById('urlForm').addEventListener('submit', function(event) {
  event.preventDefault(); // מניעת שליחת הטופס

  var url = document.getElementById('url').value.trim(); // להוריד רווחים מיותרים
  var loader = document.getElementById('loader');
  var resultElement = document.getElementById('result');

  // ניקוי התוצאה הקודמת
  resultElement.innerHTML = "";
  document.getElementById("report").style.display = "none"; // הסתרת הדוח הקודם אם היה
  loader.style.display = 'block'; // הצגת הספינר

  if (!url) {
    resultElement.innerHTML = "No URL was entered";
    loader.style.display = 'none';
    return;
  }

  if (!isValidUrl(url)) {
    resultElement.innerHTML = "The URL is not valid";
    loader.style.display = 'none';
    return;
  }

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url; // ברירת מחדל ל-https
  }

  // שליחה לשרת לבדיקה
  fetch('/check-url', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url: url })
  })
  .then(response => response.json())
  .then(data => {
    loader.style.display = 'none';
    if (data.error) {
      resultElement.innerHTML = "Error: " + data.error;
      return;
    }
    updateReport(data);
    updateTrianglePosition(data);
  })
  .catch(error => {
    loader.style.display = 'none';
    resultElement.innerHTML = "Error checking the URL: " + error.message;
  });
});

// פונקציה לבדוק אם ה-URL חוקי
function isValidUrl(url) {
  var pattern = new RegExp(
    '^(https?:\\/\\/)?' +
    '((([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})|' +
    'localhost|' +
    '\\d{1,3}(\\.\\d{1,3}){3})' +
    '(\\:\\d+)?(\\/[-a-zA-Z0-9@:%._\\+~#=]*)*' +
    '(\\?[;&a-zA-Z0-9%_\\+=-]*)?' +
    '(\\#[-a-zA-Z0-9_]*)?$',
    'i'
  );
  return pattern.test(url);
}

// פונקציה לעדכון הדוח
function updateReport(data) {
  document.getElementById("ssl-info").innerText = data.ssl_status;
  document.getElementById("hsts-info").innerText = data.hsts_status;
  document.getElementById("https-info").innerText = data.https_redirect_status;
  document.getElementById("safe-info").innerText = data.safe_browsing || "Not Available";
  document.getElementById("csp-info").innerText = data.csp_status || "Not Available";
  document.getElementById("x_frame_options_info").innerText = data.x_frame_status || "Not Available";
  document.getElementById("x_xss_protection_info").innerText = data.x_xss_protection_status || "Not Available";
  document.getElementById("report").style.display = "block";
}

// פונקציה לעדכון הסקאלה והחץ

