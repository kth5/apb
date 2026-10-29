/*
 * APB farm admin panel. ES5 only (no arrow functions, template literals,
 * let/const, Promise, fetch) so it runs in old browsers. Never assign
 * server data to innerHTML; build nodes and use textContent.
 */
(function () {
  'use strict';

  var root = document.getElementById('admin');
  if (!root || !window.XMLHttpRequest || !document.querySelector || !window.JSON) {
    return;
  }

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
  var backdrop = root.querySelector('.dialog-backdrop');
  var openDialogEl = null;
  var lastFocus = null;

  function each(list, fn) {
    for (var i = 0; i < list.length; i++) {
      fn(list[i], i);
    }
  }

  function hasClass(el, name) {
    return (' ' + el.className + ' ').indexOf(' ' + name + ' ') !== -1;
  }

  function addClass(el, name) {
    if (!hasClass(el, name)) {
      el.className = (el.className + ' ' + name).replace(/^\s+/, '');
    }
  }

  function removeClass(el, name) {
    el.className = (' ' + el.className + ' ').replace(' ' + name + ' ', ' ').replace(/^\s+|\s+$/g, '');
  }

  function text(el, value) {
    if ('textContent' in el) {
      el.textContent = value;
    } else {
      el.innerText = value;
    }
  }

  function el(tag, className, content) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (content !== undefined && content !== null) {
      text(node, String(content));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function findAction(target) {
    while (target && target !== document) {
      if (target.getAttribute && target.getAttribute('data-action')) {
        return target;
      }
      target = target.parentNode;
    }
    return null;
  }

  function messageFor(form) {
    return form.querySelector('.message');
  }

  function setMessage(target, message, isError) {
    if (!target) {
      return;
    }
    target.className = 'message alert ' + (isError ? 'alert-error' : 'alert-success');
    text(target, message);
  }

  function clearMessage(target) {
    if (target) {
      target.className = 'message';
      text(target, '');
    }
  }

  function field(form, name) {
    return form.elements[name];
  }

  function valueOf(form, name) {
    var input = field(form, name);
    return input ? input.value : '';
  }

  function encodeForm(data) {
    var parts = [];
    for (var key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key) && data[key] !== null && data[key] !== undefined) {
        parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(data[key])));
      }
    }
    return parts.join('&');
  }

  function errorText(data, status) {
    if (data) {
      if (typeof data.detail === 'string') {
        return data.detail;
      }
      if (data.detail && data.detail.length && data.detail[0].msg) {
        return data.detail[0].msg;
      }
      if (data.detail && data.detail.detail) {
        return data.detail.detail;
      }
      if (data.message) {
        return data.message;
      }
    }
    return status ? 'Request failed (HTTP ' + status + ')' : 'Network error. Please try again.';
  }

  // body: {json: object} or {form: object}; callback(errorMessage, data)
  function request(method, url, body, callback) {
    var xhr = new XMLHttpRequest();
    var payload = null;
    xhr.open(method, url, true);
    xhr.setRequestHeader('Accept', 'application/json');
    if (csrfToken) {
      xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    }
    if (body && body.form) {
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      payload = encodeForm(body.form);
    } else if (body && body.json !== undefined) {
      xhr.setRequestHeader('Content-Type', 'application/json');
      payload = JSON.stringify(body.json);
    }
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) {
        return;
      }
      var data = null;
      try {
        data = xhr.responseText ? JSON.parse(xhr.responseText) : null;
      } catch (e) {
        data = null;
      }
      var ok = xhr.status >= 200 && xhr.status < 300 && !(data && data.success === false);
      callback(ok ? null : errorText(data, xhr.status), data);
    };
    xhr.send(payload);
  }

  function reloadSoon() {
    window.setTimeout(function () {
      window.location.reload();
    }, 800);
  }

  // Dialogs

  function openDialog(id) {
    var dialog = document.getElementById(id);
    lastFocus = document.activeElement;
    openDialogEl = dialog;
    removeClass(backdrop, 'hidden');
    removeClass(dialog, 'hidden');
    clearMessage(dialog.querySelector('.message'));
    var first = dialog.querySelector('input:not([type="hidden"]):not([readonly]), select');
    if (first) {
      first.focus();
    }
  }

  function closeDialog() {
    if (!openDialogEl) {
      return;
    }
    addClass(openDialogEl, 'hidden');
    addClass(backdrop, 'hidden');
    openDialogEl = null;
    if (lastFocus && lastFocus.focus) {
      lastFocus.focus();
    }
  }

  // Users

  function editUser(button) {
    var form = root.querySelector('[data-form="edit-user"]');
    field(form, 'user_id').value = button.getAttribute('data-user-id');
    field(form, 'username').value = button.getAttribute('data-username');
    field(form, 'role').value = button.getAttribute('data-role');
    field(form, 'email').value = button.getAttribute('data-email');
    field(form, 'email_notifications').checked = button.getAttribute('data-notifications') === 'true';
    openDialog('edit-user-dialog');
  }

  function saveUser(form) {
    var userId = valueOf(form, 'user_id');
    var base = '/auth/users/' + encodeURIComponent(userId);
    var message = messageFor(form);
    var steps = [
      ['PUT', base + '/role', {json: {role: valueOf(form, 'role')}}],
      ['PUT', base + '/email-notifications', {json: {enabled: field(form, 'email_notifications').checked}}],
      ['PUT', base + '/email', {json: {email: valueOf(form, 'email') || null}}]
    ];
    function next(index) {
      if (index >= steps.length) {
        setMessage(message, 'User updated.', false);
        reloadSoon();
        return;
      }
      var step = steps[index];
      request(step[0], step[1], step[2], function (error) {
        if (error) {
          setMessage(message, error, true);
          return;
        }
        next(index + 1);
      });
    }
    clearMessage(message);
    next(0);
  }

  function addUser(form) {
    var message = messageFor(form);
    clearMessage(message);
    request('POST', '/auth/users', {json: {
      username: valueOf(form, 'username'),
      password: valueOf(form, 'password'),
      email: valueOf(form, 'email') || null,
      role: valueOf(form, 'role')
    }}, function (error) {
      if (error) {
        setMessage(message, error, true);
        return;
      }
      setMessage(message, 'User created.', false);
      form.reset();
      reloadSoon();
    });
  }

  function deleteUser(button) {
    var username = button.getAttribute('data-username');
    if (!window.confirm('Delete user "' + username + '"? This cannot be undone.')) {
      return;
    }
    request('DELETE', '/auth/users/' + encodeURIComponent(button.getAttribute('data-user-id')), null, function (error) {
      if (error) {
        window.alert('Failed to delete user: ' + error);
        return;
      }
      window.location.reload();
    });
  }

  function resetMfa(button) {
    var username = button.getAttribute('data-username');
    if (!window.confirm('Remove the authenticator app, security keys and recovery codes of "' + username + '" and log them out everywhere?')) {
      return;
    }
    request('DELETE', '/auth/users/' + encodeURIComponent(button.getAttribute('data-user-id')) + '/2fa', null, function (error) {
      if (error) {
        window.alert('Failed to reset 2FA: ' + error);
        return;
      }
      window.location.reload();
    });
  }

  // SMTP

  function smtpForm() {
    return root.querySelector('[data-form="smtp"]');
  }

  function loadSmtp() {
    var form = smtpForm();
    request('GET', '/admin/smtp', null, function (error, config) {
      if (error) {
        setMessage(messageFor(form), error, true);
        return;
      }
      if (!config) {
        return;
      }
      field(form, 'server').value = config.server || '';
      field(form, 'port').value = config.port || 587;
      field(form, 'username').value = config.username || '';
      field(form, 'password').value = '';
      field(form, 'from_email').value = config.from_email || '';
      field(form, 'from_name').value = config.from_name || '';
      field(form, 'use_tls').checked = config.use_tls !== false;
    });
  }

  function saveSmtp(form) {
    var message = messageFor(form);
    clearMessage(message);
    request('POST', '/admin/smtp', {json: {
      server: valueOf(form, 'server'),
      port: parseInt(valueOf(form, 'port'), 10),
      username: valueOf(form, 'username') || null,
      password: valueOf(form, 'password') || null,
      from_email: valueOf(form, 'from_email') || null,
      from_name: valueOf(form, 'from_name') || null,
      use_tls: field(form, 'use_tls').checked
    }}, function (error) {
      if (error) {
        setMessage(message, error, true);
        return;
      }
      field(form, 'password').value = '';
      setMessage(message, 'SMTP configuration saved.', false);
    });
  }

  function deleteSmtp() {
    var form = smtpForm();
    if (!window.confirm('Delete the SMTP configuration? Email notifications will stop.')) {
      return;
    }
    request('DELETE', '/admin/smtp', null, function (error) {
      if (error) {
        setMessage(messageFor(form), error, true);
        return;
      }
      form.reset();
      setMessage(messageFor(form), 'SMTP configuration deleted.', false);
    });
  }

  function testSmtp(form) {
    var message = messageFor(form);
    clearMessage(message);
    request('POST', '/admin/smtp/test', {json: {test_email: valueOf(form, 'test_email')}}, function (error, data) {
      setMessage(message, error || (data && data.message) || 'Test email sent.', !!error);
    });
  }

  // Repositories

  var repositories = {};

  function repositoryButton(label, action, repoId, className) {
    var button = el('button', 'button-small' + (className ? ' ' + className : ''), label);
    button.type = 'button';
    button.setAttribute('data-action', action);
    button.setAttribute('data-repo-id', String(repoId));
    return button;
  }

  function renderRepositories(list) {
    var container = document.getElementById('repositories-list');
    clear(container);
    repositories = {};
    if (!list || !list.length) {
      container.appendChild(el('p', 'muted', 'No repositories configured.'));
      return;
    }
    var table = el('table', 'data-table stack');
    var head = el('thead');
    var headRow = el('tr');
    each(['Name', 'URL', 'GPG key', 'Description', 'Status', 'Actions'], function (label) {
      var th = el('th', null, label);
      th.setAttribute('scope', 'col');
      headRow.appendChild(th);
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var body = el('tbody');
    each(list, function (repo) {
      repositories[repo.id] = repo;
      var row = el('tr');
      var cells = [
        ['Name', repo.name],
        ['URL', repo.url],
        ['GPG key', repo.gpg_key_id],
        ['Description', repo.description || '-']
      ];
      each(cells, function (cell) {
        var td = el('td', null, cell[1]);
        td.setAttribute('data-label', cell[0]);
        row.appendChild(td);
      });
      var statusCell = el('td');
      statusCell.setAttribute('data-label', 'Status');
      statusCell.appendChild(el('span', 'badge badge-' + (repo.is_active ? 'active' : 'inactive'), repo.is_active ? 'active' : 'inactive'));
      row.appendChild(statusCell);
      var actions = el('td');
      actions.setAttribute('data-label', 'Actions');
      actions.appendChild(repositoryButton('Edit', 'edit-repository', repo.id));
      actions.appendChild(document.createTextNode(' '));
      actions.appendChild(repositoryButton(repo.is_active ? 'Disable' : 'Enable', 'toggle-repository', repo.id));
      actions.appendChild(document.createTextNode(' '));
      actions.appendChild(repositoryButton('Delete', 'delete-repository', repo.id, 'button-danger'));
      row.appendChild(actions);
      body.appendChild(row);
    });
    table.appendChild(body);
    var scroll = el('div', 'table-scroll');
    scroll.appendChild(table);
    container.appendChild(scroll);
  }

  function loadRepositories() {
    request('GET', '/admin/repositories', null, function (error, data) {
      if (error) {
        var container = document.getElementById('repositories-list');
        clear(container);
        container.appendChild(el('p', 'alert alert-error', error));
        return;
      }
      renderRepositories(data && data.repositories);
    });
  }

  function addRepository(form) {
    var message = messageFor(form);
    clearMessage(message);
    request('POST', '/admin/repositories', {form: {
      name: valueOf(form, 'name'),
      url: valueOf(form, 'url'),
      gpg_key_id: valueOf(form, 'gpg_key_id'),
      description: valueOf(form, 'description')
    }}, function (error, data) {
      if (error) {
        setMessage(message, error, true);
        return;
      }
      form.reset();
      setMessage(message, (data && data.message) || 'Repository added.', false);
      loadRepositories();
    });
  }

  function editRepository(button) {
    var repo = repositories[button.getAttribute('data-repo-id')];
    if (!repo) {
      return;
    }
    var form = root.querySelector('[data-form="edit-repository"]');
    field(form, 'repo_id').value = repo.id;
    field(form, 'name').value = repo.name || '';
    field(form, 'url').value = repo.url || '';
    field(form, 'gpg_key_id').value = repo.gpg_key_id || '';
    field(form, 'description').value = repo.description || '';
    field(form, 'is_active').checked = !!repo.is_active;
    openDialog('edit-repository-dialog');
  }

  function updateRepository(repoId, data, callback) {
    request('PUT', '/admin/repositories/' + encodeURIComponent(repoId), {form: data}, callback);
  }

  function saveRepository(form) {
    var message = messageFor(form);
    clearMessage(message);
    updateRepository(valueOf(form, 'repo_id'), {
      name: valueOf(form, 'name'),
      url: valueOf(form, 'url'),
      gpg_key_id: valueOf(form, 'gpg_key_id'),
      description: valueOf(form, 'description'),
      is_active: field(form, 'is_active').checked ? 'true' : 'false'
    }, function (error) {
      if (error) {
        setMessage(message, error, true);
        return;
      }
      closeDialog();
      loadRepositories();
    });
  }

  function toggleRepository(button) {
    var repo = repositories[button.getAttribute('data-repo-id')];
    if (!repo) {
      return;
    }
    updateRepository(repo.id, {is_active: repo.is_active ? 'false' : 'true'}, function (error) {
      if (error) {
        window.alert(error);
        return;
      }
      loadRepositories();
    });
  }

  function deleteRepository(button) {
    var repo = repositories[button.getAttribute('data-repo-id')];
    if (!repo || !window.confirm('Delete repository "' + repo.name + '"?')) {
      return;
    }
    request('DELETE', '/admin/repositories/' + encodeURIComponent(repo.id), null, function (error) {
      if (error) {
        window.alert(error);
        return;
      }
      loadRepositories();
    });
  }

  // Cache

  function cacheMessage() {
    return document.getElementById('cache').querySelector('.message');
  }

  function loadCache() {
    var container = document.getElementById('cache-status');
    request('GET', '/admin/cache', null, function (error, data) {
      clear(container);
      if (error) {
        container.appendChild(el('p', 'alert alert-error', error));
        return;
      }
      if (!data.enabled) {
        container.appendChild(el('p', 'alert alert-warning', data.message || 'Caching is disabled'));
        return;
      }
      var rows = [
        ['Status', 'enabled'],
        ['Retention', data.retention_days + ' days'],
        ['Artifacts', data.total_artifacts + ' files'],
        ['Size', data.total_size_mb + ' MB'],
        ['Expired', data.expired_artifacts + ' files']
      ];
      if (data.oldest_cache_age_days) {
        rows.push(['Oldest entry', data.oldest_cache_age_days + ' days old']);
      }
      var list = el('dl', 'details');
      each(rows, function (row) {
        list.appendChild(el('dt', null, row[0]));
        list.appendChild(el('dd', null, row[1]));
      });
      container.appendChild(list);
    });
  }

  function cleanupCache() {
    var message = cacheMessage();
    clearMessage(message);
    request('POST', '/admin/cache/cleanup', null, function (error, data) {
      setMessage(message, error || (data && data.message) || 'Cache cleaned up.', !!error);
      loadCache();
    });
  }

  // Wiring

  var actions = {
    'edit-user': editUser,
    'delete-user': deleteUser,
    'reset-mfa': resetMfa,
    'reload-smtp': loadSmtp,
    'delete-smtp': deleteSmtp,
    'edit-repository': editRepository,
    'toggle-repository': toggleRepository,
    'delete-repository': deleteRepository,
    'reload-cache': loadCache,
    'cleanup-cache': cleanupCache,
    'close-dialog': closeDialog
  };

  var forms = {
    'add-user': addUser,
    'edit-user': saveUser,
    'smtp': saveSmtp,
    'smtp-test': testSmtp,
    'add-repository': addRepository,
    'edit-repository': saveRepository
  };

  root.addEventListener('click', function (event) {
    var target = findAction(event.target);
    if (!target) {
      return;
    }
    var handler = actions[target.getAttribute('data-action')];
    if (handler) {
      event.preventDefault();
      handler(target);
    }
  }, false);

  root.addEventListener('submit', function (event) {
    var form = event.target;
    var handler = forms[form.getAttribute('data-form')];
    if (handler) {
      event.preventDefault();
      handler(form);
    }
  }, false);

  document.addEventListener('keydown', function (event) {
    if (openDialogEl && (event.keyCode === 27 || event.key === 'Escape')) {
      closeDialog();
    }
  }, false);

  each(root.querySelectorAll('.js-only'), function (node) {
    removeClass(node, 'hidden');
  });

  loadSmtp();
  loadRepositories();
  loadCache();
}());
