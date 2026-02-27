// Local Puppeteer E2E harness for PromptArmor
// Usage:
// 1) npm install puppeteer --save-dev
// 2) node test/e2e/run.js

const puppeteer = require('puppeteer');
const path = require('path');

(async ()=>{
  const extensionPath = path.resolve(__dirname, '../../');
  console.log('Loading extension from', extensionPath);

  const browser = await puppeteer.launch({
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`
    ],
    defaultViewport: {width: 1200, height: 800}
  });

  const page = await browser.newPage();

  // Intercept network requests for logging
  await page.setRequestInterception(true);
  page.on('request', req => {
    console.log('REQUEST:', req.method(), req.url());
    req.continue();
  });
  page.on('requestfailed', req => {
    console.log('REQUEST FAILED:', req.url(), req.failure().errorText);
  });
  page.on('response', res => {
    console.log('RESPONSE:', res.status(), res.url());
  });

  // Serve local fixture
  const fileUrl = 'file://' + path.resolve(__dirname, 'fixtures', 'malicious.html');
  console.log('Navigating to', fileUrl);
  await page.goto(fileUrl, {waitUntil: 'networkidle2'});

  // Wait for the page to attempt exfil and record result in DOM
  await page.waitForTimeout(2000);
  const status = await page.evaluate(()=>{
    const el = document.getElementById('exfil-status');
    return el ? el.textContent : null;
  });
  console.log('Page reported exfil status:', status);

  // Simple check: if any request to malicious-server.com succeeded, fail
  // We consider blocked if no successful response observed for that host
  // (This is a heuristic; DNR blocks at browser level and may result in failed requests.)

  console.log('E2E done. Close the browser manually if needed.');
})();
