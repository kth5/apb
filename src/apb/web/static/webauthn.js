/*
 * Security key (WebAuthn) prompts for the farm login and account pages.
 * ES5 syntax like the other scripts; WebAuthn itself only exists in browsers
 * that also have Promise. Forms marked data-webauthn="get" or "create" carry
 * their options in a JSON <script class="webauthn-options"> and are submitted
 * normally with the JSON-encoded credential in the hidden "credential" field.
 */
(function () {
  'use strict';

  if (!window.PublicKeyCredential || !navigator.credentials || !window.JSON || !window.atob || !document.querySelectorAll) {
    return;
  }

  function each(list, fn) {
    for (var i = 0; i < list.length; i++) {
      fn(list[i]);
    }
  }

  function toBuffer(value) {
    var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    var binary = window.atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function toBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodeDescriptors(list) {
    each(list || [], function (descriptor) {
      descriptor.id = toBuffer(descriptor.id);
    });
  }

  function publicKeyOptions(form, mode) {
    var options = JSON.parse(form.querySelector('.webauthn-options').textContent).publicKey;
    options.challenge = toBuffer(options.challenge);
    if (mode === 'create') {
      options.user.id = toBuffer(options.user.id);
      decodeDescriptors(options.excludeCredentials);
    } else {
      decodeDescriptors(options.allowCredentials);
    }
    return options;
  }

  function encodeCredential(credential) {
    var response = credential.response;
    var encoded = {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      response: {clientDataJSON: toBase64Url(response.clientDataJSON)},
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
    };
    if (credential.authenticatorAttachment) {
      encoded.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (response.attestationObject) {
      encoded.response.attestationObject = toBase64Url(response.attestationObject);
    }
    if (response.authenticatorData) {
      encoded.response.authenticatorData = toBase64Url(response.authenticatorData);
      encoded.response.signature = toBase64Url(response.signature);
      if (response.userHandle) {
        encoded.response.userHandle = toBase64Url(response.userHandle);
      }
    }
    return encoded;
  }

  function setMessage(form, message) {
    var target = form.querySelector('.message');
    if (target) {
      target.className = 'message alert alert-error';
      target.textContent = message;
    }
  }

  function errorMessage(error) {
    if (error && error.name === 'NotAllowedError') {
      return 'The security key prompt was cancelled or timed out.';
    }
    if (error && error.name === 'InvalidStateError') {
      return 'This security key is already registered.';
    }
    return 'Security key error: ' + (error && error.message ? error.message : 'unknown error');
  }

  function showJsOnly(node) {
    while (node && node !== document) {
      if (node.className && (' ' + node.className + ' ').indexOf(' js-only ') !== -1) {
        node.className = node.className.replace(/(^|\s)hidden(\s|$)/, ' ').replace(/^\s+|\s+$/g, '');
      }
      node = node.parentNode;
    }
  }

  each(document.querySelectorAll('form[data-webauthn]'), function (form) {
    var mode = form.getAttribute('data-webauthn');
    var credentialField = form.elements.credential;
    var button = form.querySelector('button[type="submit"]');
    showJsOnly(form);

    form.addEventListener('submit', function (event) {
      if (credentialField.value) {
        return;
      }
      event.preventDefault();
      if (form.checkValidity && !form.checkValidity()) {
        return;
      }
      button.disabled = true;
      var ceremony = mode === 'create'
        ? navigator.credentials.create({publicKey: publicKeyOptions(form, mode)})
        : navigator.credentials.get({publicKey: publicKeyOptions(form, mode)});
      ceremony.then(function (credential) {
        credentialField.value = JSON.stringify(encodeCredential(credential));
        form.submit();
      }, function (error) {
        button.disabled = false;
        setMessage(form, errorMessage(error));
      });
    }, false);
  });
}());
