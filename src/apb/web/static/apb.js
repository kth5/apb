/*
 * APB web UI progressive enhancement. ES5 only; every page works without it.
 *
 * Pages whose <main> has data-poll="N" are re-fetched every N seconds and only
 * their [data-poll-region] element is replaced. One request at a time, paused
 * while the browser tab is hidden, exponential backoff after errors, and the
 * loop stops once a response no longer asks to be polled.
 */
(function () {
  'use strict';

  var MAX_DELAY_SECONDS = 300;
  var main = document.getElementById('main');
  if (!main) {
    return;
  }

  if (document.addEventListener) {
    document.addEventListener('submit', function (event) {
      var form = event.target;
      var question = form && form.getAttribute ? form.getAttribute('data-confirm') : null;
      if (question && !window.confirm(question)) {
        event.preventDefault();
      }
    }, false);
  }

  var pollSeconds = parseInt(main.getAttribute('data-poll') || '0', 10);
  if (!pollSeconds || pollSeconds < 1) {
    return;
  }

  // With scripting on, the <noscript> meta refresh is ignored, so browsers
  // too old for in-place updates get a plain reload instead.
  if (!window.XMLHttpRequest || !document.querySelector || !document.addEventListener) {
    window.setTimeout(function () {
      window.location.reload();
    }, pollSeconds * 1000);
    return;
  }

  var delaySeconds = pollSeconds;
  var timer = null;
  var inFlight = false;
  var stopped = false;

  function isHidden() {
    return document.hidden === true || document.webkitHidden === true;
  }

  function schedule(seconds) {
    if (stopped) {
      return;
    }
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(poll, seconds * 1000);
  }

  function swap(html) {
    var container = document.createElement('div');
    container.innerHTML = html;
    var fresh = container.querySelector('[data-poll-region]');
    var current = document.querySelector('[data-poll-region]');
    if (!fresh || !current) {
      return false;
    }
    current.parentNode.replaceChild(fresh, current);
    var freshMain = container.querySelector('#main');
    if (!freshMain || !freshMain.getAttribute('data-poll')) {
      stopped = true;
    }
    return true;
  }

  function poll() {
    timer = null;
    if (stopped || inFlight || isHidden()) {
      return;
    }
    inFlight = true;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', window.location.pathname + window.location.search, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) {
        return;
      }
      inFlight = false;
      var swapped = xhr.status > 0 && swap(xhr.responseText);
      if (swapped && xhr.status >= 200 && xhr.status < 300) {
        delaySeconds = pollSeconds;
      } else {
        delaySeconds = Math.min(delaySeconds * 2, MAX_DELAY_SECONDS);
      }
      schedule(delaySeconds);
    };
    xhr.send(null);
  }

  function onVisibilityChange() {
    if (!isHidden() && !timer && !inFlight) {
      poll();
    }
  }

  document.addEventListener('visibilitychange', onVisibilityChange, false);
  document.addEventListener('webkitvisibilitychange', onVisibilityChange, false);
  schedule(delaySeconds);
}());
