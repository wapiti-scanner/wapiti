(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

(function () {
  /**
   * Predefine hint text to display.
   *
   * @since 1.5.6
   * @since 1.6.4 Added a new macros - {remaining}.
   *
   * @param {string} hintText Hint text.
   * @param {number} count Current count.
   * @param {number} limit Limit to.
   *
   * @returns {string} Predefined hint text.
   */
  function renderHint(hintText, count, limit) {
    return hintText.replace('{count}', count).replace('{limit}', limit).replace('{remaining}', limit - count);
  }

  /**
   * Create HTMLElement hint element with text.
   *
   * @since 1.5.6
   *
   * @param {number} formId Form id.
   * @param {number} fieldId Form field id.
   * @param {string} text Text to hint element.
   *
   * @returns {object} HTMLElement hint element with text.
   */
  function createHint(formId, fieldId, text) {
    var hint = document.createElement('div');
    hint.classList.add('wpforms-field-limit-text');
    hint.id = 'wpforms-field-limit-text-' + formId + '-' + fieldId;
    hint.setAttribute('aria-live', 'polite');
    hint.textContent = text;
    return hint;
  }

  /**
   * Keyup/Keydown event higher order function for characters limit.
   *
   * @since 1.5.6
   *
   * @param {object} hint HTMLElement hint element.
   * @param {number} limit Max allowed number of characters.
   *
   * @returns {Function} Handler function.
   */
  function checkCharacters(hint, limit) {
    return function (e) {
      hint.textContent = renderHint(window.wpforms_settings.val_limit_characters, this.value.length, limit);
    };
  }

  /**
   * Count words in the string.
   *
   * @since 1.6.2
   *
   * @param {string} string String value.
   *
   * @returns {number} Words count.
   */
  function countWords(string) {
    if (typeof string !== 'string') {
      return 0;
    }
    if (!string.length) {
      return 0;
    }
    [/([A-Z]+),([A-Z]+)/gi, /([0-9]+),([A-Z]+)/gi, /([A-Z]+),([0-9]+)/gi].forEach(function (pattern) {
      string = string.replace(pattern, '$1, $2');
    });
    return string.split(/\s+/).length;
  }

  /**
   * Keyup/Keydown event higher order function for words limit.
   *
   * @since 1.5.6
   *
   * @param {object} hint HTMLElement hint element.
   * @param {number} limit Max allowed number of characters.
   *
   * @returns {Function} Handler function.
   */
  function checkWords(hint, limit) {
    return function (e) {
      var value = this.value.trim(),
        words = countWords(value);
      hint.textContent = renderHint(window.wpforms_settings.val_limit_words, words, limit);

      // We should prevent the keys: Enter, Space, Comma.
      if ([13, 32, 188].indexOf(e.keyCode) > -1 && words >= limit) {
        e.preventDefault();
      }
    };
  }

  /**
   * Get passed text from clipboard.
   *
   * @since 1.5.6
   *
   * @param {ClipboardEvent} e Clipboard event.
   *
   * @returns {string} Text from clipboard.
   */
  function getPastedText(e) {
    if (window.clipboardData && window.clipboardData.getData) {
      // IE

      return window.clipboardData.getData('Text');
    } else if (e.clipboardData && e.clipboardData.getData) {
      return e.clipboardData.getData('text/plain');
    }
  }

  /**
   * Paste event higher order function for characters limit.
   *
   * @since 1.6.7.1
   *
   * @param {number} limit Max allowed number of characters.
   *
   * @returns {Function} Event handler.
   */
  function pasteText(limit) {
    return function (e) {
      e.preventDefault();
      var pastedText = getPastedText(e),
        newPosition = this.selectionStart + pastedText.length,
        newText = this.value.substring(0, this.selectionStart) + pastedText + this.value.substring(this.selectionStart);
      this.value = newText.substring(0, limit);
      this.setSelectionRange(newPosition, newPosition);
    };
  }

  /**
   * Limit string length to a certain number of words, preserving line breaks.
   *
   * @since 1.6.8
   *
   * @param {string} text  Text.
   * @param {number} limit Max allowed number of words.
   *
   * @returns {string} Text with the limited number of words.
   */
  function limitWords(text, limit) {
    var separators,
      newTextArray,
      result = '';

    // Regular expression pattern: match any space character.
    var regEx = /\s+/g;

    // Store separators for further join.
    separators = text.trim().match(regEx) || [];

    // Split the new text by regular expression.
    newTextArray = text.split(regEx);

    // Limit the number of words.
    newTextArray.splice(limit, newTextArray.length);

    // Join the words together using stored separators.
    for (var i = 0; i < newTextArray.length; i++) {
      result += newTextArray[i] + (separators[i] || '');
    }
    return result.trim();
  }

  /**
   * Paste event higher order function for words limit.
   *
   * @since 1.5.6
   *
   * @param {number} limit Max allowed number of words.
   *
   * @returns {Function} Event handler.
   */
  function pasteWords(limit) {
    return function (e) {
      e.preventDefault();
      var pastedText = getPastedText(e),
        newPosition = this.selectionStart + pastedText.length,
        newText = this.value.substring(0, this.selectionStart) + pastedText + this.value.substring(this.selectionStart);
      this.value = limitWords(newText, limit);
      this.setSelectionRange(newPosition, newPosition);
    };
  }

  /**
   * Array.form polyfill.
   *
   * @since 1.5.6
   *
   * @param {object} el Iterator.
   *
   * @returns {object} Array.
   */
  function arrFrom(el) {
    return [].slice.call(el);
  }

  /**
   * DOMContentLoaded handler.
   *
   * @since 1.5.6
   */
  function ready() {
    arrFrom(document.querySelectorAll('.wpforms-limit-characters-enabled')).map(function (e) {
      var limit = parseInt(e.dataset.textLimit, 10) || 0;
      e.value = e.value.slice(0, limit);
      var hint = createHint(e.dataset.formId, e.dataset.fieldId, renderHint(window.wpforms_settings.val_limit_characters, e.value.length, limit));
      var fn = checkCharacters(hint, limit);
      e.parentNode.appendChild(hint);
      e.addEventListener('keydown', fn);
      e.addEventListener('keyup', fn);
      e.addEventListener('paste', pasteText(limit));
    });
    arrFrom(document.querySelectorAll('.wpforms-limit-words-enabled')).map(function (e) {
      var limit = parseInt(e.dataset.textLimit, 10) || 0;
      e.value = limitWords(e.value, limit);
      var hint = createHint(e.dataset.formId, e.dataset.fieldId, renderHint(window.wpforms_settings.val_limit_words, countWords(e.value.trim()), limit));
      var fn = checkWords(hint, limit);
      e.parentNode.appendChild(hint);
      e.addEventListener('keydown', fn);
      e.addEventListener('keyup', fn);
      e.addEventListener('paste', pasteWords(limit));
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }
})();
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJyZW5kZXJIaW50IiwiaGludFRleHQiLCJjb3VudCIsImxpbWl0IiwicmVwbGFjZSIsImNyZWF0ZUhpbnQiLCJmb3JtSWQiLCJmaWVsZElkIiwidGV4dCIsImhpbnQiLCJkb2N1bWVudCIsImNyZWF0ZUVsZW1lbnQiLCJjbGFzc0xpc3QiLCJhZGQiLCJpZCIsInNldEF0dHJpYnV0ZSIsInRleHRDb250ZW50IiwiY2hlY2tDaGFyYWN0ZXJzIiwiZSIsIndpbmRvdyIsIndwZm9ybXNfc2V0dGluZ3MiLCJ2YWxfbGltaXRfY2hhcmFjdGVycyIsInZhbHVlIiwibGVuZ3RoIiwiY291bnRXb3JkcyIsInN0cmluZyIsImZvckVhY2giLCJwYXR0ZXJuIiwic3BsaXQiLCJjaGVja1dvcmRzIiwidHJpbSIsIndvcmRzIiwidmFsX2xpbWl0X3dvcmRzIiwiaW5kZXhPZiIsImtleUNvZGUiLCJwcmV2ZW50RGVmYXVsdCIsImdldFBhc3RlZFRleHQiLCJjbGlwYm9hcmREYXRhIiwiZ2V0RGF0YSIsInBhc3RlVGV4dCIsInBhc3RlZFRleHQiLCJuZXdQb3NpdGlvbiIsInNlbGVjdGlvblN0YXJ0IiwibmV3VGV4dCIsInN1YnN0cmluZyIsInNldFNlbGVjdGlvblJhbmdlIiwibGltaXRXb3JkcyIsInNlcGFyYXRvcnMiLCJuZXdUZXh0QXJyYXkiLCJyZXN1bHQiLCJyZWdFeCIsIm1hdGNoIiwic3BsaWNlIiwiaSIsInBhc3RlV29yZHMiLCJhcnJGcm9tIiwiZWwiLCJzbGljZSIsImNhbGwiLCJyZWFkeSIsInF1ZXJ5U2VsZWN0b3JBbGwiLCJtYXAiLCJwYXJzZUludCIsImRhdGFzZXQiLCJ0ZXh0TGltaXQiLCJmbiIsInBhcmVudE5vZGUiLCJhcHBlbmRDaGlsZCIsImFkZEV2ZW50TGlzdGVuZXIiLCJyZWFkeVN0YXRlIl0sInNvdXJjZXMiOlsiZmFrZV85ZmYyOThjYy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbiggZnVuY3Rpb24oKSB7XG5cblx0LyoqXG5cdCAqIFByZWRlZmluZSBoaW50IHRleHQgdG8gZGlzcGxheS5cblx0ICpcblx0ICogQHNpbmNlIDEuNS42XG5cdCAqIEBzaW5jZSAxLjYuNCBBZGRlZCBhIG5ldyBtYWNyb3MgLSB7cmVtYWluaW5nfS5cblx0ICpcblx0ICogQHBhcmFtIHtzdHJpbmd9IGhpbnRUZXh0IEhpbnQgdGV4dC5cblx0ICogQHBhcmFtIHtudW1iZXJ9IGNvdW50IEN1cnJlbnQgY291bnQuXG5cdCAqIEBwYXJhbSB7bnVtYmVyfSBsaW1pdCBMaW1pdCB0by5cblx0ICpcblx0ICogQHJldHVybnMge3N0cmluZ30gUHJlZGVmaW5lZCBoaW50IHRleHQuXG5cdCAqL1xuXHRmdW5jdGlvbiByZW5kZXJIaW50KCBoaW50VGV4dCwgY291bnQsIGxpbWl0ICkge1xuXG5cdFx0cmV0dXJuIGhpbnRUZXh0LnJlcGxhY2UoICd7Y291bnR9JywgY291bnQgKS5yZXBsYWNlKCAne2xpbWl0fScsIGxpbWl0ICkucmVwbGFjZSggJ3tyZW1haW5pbmd9JywgbGltaXQgLSBjb3VudCApO1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZSBIVE1MRWxlbWVudCBoaW50IGVsZW1lbnQgd2l0aCB0ZXh0LlxuXHQgKlxuXHQgKiBAc2luY2UgMS41LjZcblx0ICpcblx0ICogQHBhcmFtIHtudW1iZXJ9IGZvcm1JZCBGb3JtIGlkLlxuXHQgKiBAcGFyYW0ge251bWJlcn0gZmllbGRJZCBGb3JtIGZpZWxkIGlkLlxuXHQgKiBAcGFyYW0ge3N0cmluZ30gdGV4dCBUZXh0IHRvIGhpbnQgZWxlbWVudC5cblx0ICpcblx0ICogQHJldHVybnMge29iamVjdH0gSFRNTEVsZW1lbnQgaGludCBlbGVtZW50IHdpdGggdGV4dC5cblx0ICovXG5cdGZ1bmN0aW9uIGNyZWF0ZUhpbnQoIGZvcm1JZCwgZmllbGRJZCwgdGV4dCApIHtcblxuXHRcdHZhciBoaW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCggJ2RpdicgKTtcblx0XHRoaW50LmNsYXNzTGlzdC5hZGQoICd3cGZvcm1zLWZpZWxkLWxpbWl0LXRleHQnICk7XG5cdFx0aGludC5pZCA9ICd3cGZvcm1zLWZpZWxkLWxpbWl0LXRleHQtJyArIGZvcm1JZCArICctJyArIGZpZWxkSWQ7XG5cdFx0aGludC5zZXRBdHRyaWJ1dGUoICdhcmlhLWxpdmUnLCAncG9saXRlJyApO1xuXHRcdGhpbnQudGV4dENvbnRlbnQgPSB0ZXh0O1xuXG5cdFx0cmV0dXJuIGhpbnQ7XG5cdH1cblxuXHQvKipcblx0ICogS2V5dXAvS2V5ZG93biBldmVudCBoaWdoZXIgb3JkZXIgZnVuY3Rpb24gZm9yIGNoYXJhY3RlcnMgbGltaXQuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjUuNlxuXHQgKlxuXHQgKiBAcGFyYW0ge29iamVjdH0gaGludCBIVE1MRWxlbWVudCBoaW50IGVsZW1lbnQuXG5cdCAqIEBwYXJhbSB7bnVtYmVyfSBsaW1pdCBNYXggYWxsb3dlZCBudW1iZXIgb2YgY2hhcmFjdGVycy5cblx0ICpcblx0ICogQHJldHVybnMge0Z1bmN0aW9ufSBIYW5kbGVyIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gY2hlY2tDaGFyYWN0ZXJzKCBoaW50LCBsaW1pdCApIHtcblxuXHRcdHJldHVybiBmdW5jdGlvbiggZSApIHtcblxuXHRcdFx0aGludC50ZXh0Q29udGVudCA9IHJlbmRlckhpbnQoXG5cdFx0XHRcdHdpbmRvdy53cGZvcm1zX3NldHRpbmdzLnZhbF9saW1pdF9jaGFyYWN0ZXJzLFxuXHRcdFx0XHR0aGlzLnZhbHVlLmxlbmd0aCxcblx0XHRcdFx0bGltaXRcblx0XHRcdCk7XG5cdFx0fTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb3VudCB3b3JkcyBpbiB0aGUgc3RyaW5nLlxuXHQgKlxuXHQgKiBAc2luY2UgMS42LjJcblx0ICpcblx0ICogQHBhcmFtIHtzdHJpbmd9IHN0cmluZyBTdHJpbmcgdmFsdWUuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtudW1iZXJ9IFdvcmRzIGNvdW50LlxuXHQgKi9cblx0ZnVuY3Rpb24gY291bnRXb3Jkcyggc3RyaW5nICkge1xuXG5cdFx0aWYgKCB0eXBlb2Ygc3RyaW5nICE9PSAnc3RyaW5nJyApIHtcblx0XHRcdHJldHVybiAwO1xuXHRcdH1cblxuXHRcdGlmICggISBzdHJpbmcubGVuZ3RoICkge1xuXHRcdFx0cmV0dXJuIDA7XG5cdFx0fVxuXG5cdFx0W1xuXHRcdFx0LyhbQS1aXSspLChbQS1aXSspL2dpLFxuXHRcdFx0LyhbMC05XSspLChbQS1aXSspL2dpLFxuXHRcdFx0LyhbQS1aXSspLChbMC05XSspL2dpLFxuXHRcdF0uZm9yRWFjaCggZnVuY3Rpb24oIHBhdHRlcm4gKSB7XG5cdFx0XHRzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSggcGF0dGVybiwgJyQxLCAkMicgKTtcblx0XHR9ICk7XG5cblx0XHRyZXR1cm4gc3RyaW5nLnNwbGl0KCAvXFxzKy8gKS5sZW5ndGg7XG5cdH1cblxuXHQvKipcblx0ICogS2V5dXAvS2V5ZG93biBldmVudCBoaWdoZXIgb3JkZXIgZnVuY3Rpb24gZm9yIHdvcmRzIGxpbWl0LlxuXHQgKlxuXHQgKiBAc2luY2UgMS41LjZcblx0ICpcblx0ICogQHBhcmFtIHtvYmplY3R9IGhpbnQgSFRNTEVsZW1lbnQgaGludCBlbGVtZW50LlxuXHQgKiBAcGFyYW0ge251bWJlcn0gbGltaXQgTWF4IGFsbG93ZWQgbnVtYmVyIG9mIGNoYXJhY3RlcnMuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtGdW5jdGlvbn0gSGFuZGxlciBmdW5jdGlvbi5cblx0ICovXG5cdGZ1bmN0aW9uIGNoZWNrV29yZHMoIGhpbnQsIGxpbWl0ICkge1xuXG5cdFx0cmV0dXJuIGZ1bmN0aW9uKCBlICkge1xuXG5cdFx0XHR2YXIgdmFsdWUgPSB0aGlzLnZhbHVlLnRyaW0oKSxcblx0XHRcdFx0d29yZHMgPSBjb3VudFdvcmRzKCB2YWx1ZSApO1xuXG5cdFx0XHRoaW50LnRleHRDb250ZW50ID0gcmVuZGVySGludChcblx0XHRcdFx0d2luZG93LndwZm9ybXNfc2V0dGluZ3MudmFsX2xpbWl0X3dvcmRzLFxuXHRcdFx0XHR3b3Jkcyxcblx0XHRcdFx0bGltaXRcblx0XHRcdCk7XG5cblx0XHRcdC8vIFdlIHNob3VsZCBwcmV2ZW50IHRoZSBrZXlzOiBFbnRlciwgU3BhY2UsIENvbW1hLlxuXHRcdFx0aWYgKCBbIDEzLCAzMiwgMTg4IF0uaW5kZXhPZiggZS5rZXlDb2RlICkgPiAtMSAmJiB3b3JkcyA+PSBsaW1pdCApIHtcblx0XHRcdFx0ZS5wcmV2ZW50RGVmYXVsdCgpO1xuXHRcdFx0fVxuXHRcdH07XG5cdH1cblxuXHQvKipcblx0ICogR2V0IHBhc3NlZCB0ZXh0IGZyb20gY2xpcGJvYXJkLlxuXHQgKlxuXHQgKiBAc2luY2UgMS41LjZcblx0ICpcblx0ICogQHBhcmFtIHtDbGlwYm9hcmRFdmVudH0gZSBDbGlwYm9hcmQgZXZlbnQuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtzdHJpbmd9IFRleHQgZnJvbSBjbGlwYm9hcmQuXG5cdCAqL1xuXHRmdW5jdGlvbiBnZXRQYXN0ZWRUZXh0KCBlICkge1xuXG5cdFx0aWYgKCB3aW5kb3cuY2xpcGJvYXJkRGF0YSAmJiB3aW5kb3cuY2xpcGJvYXJkRGF0YS5nZXREYXRhICkgeyAvLyBJRVxuXG5cdFx0XHRyZXR1cm4gd2luZG93LmNsaXBib2FyZERhdGEuZ2V0RGF0YSggJ1RleHQnICk7XG5cdFx0fSBlbHNlIGlmICggZS5jbGlwYm9hcmREYXRhICYmIGUuY2xpcGJvYXJkRGF0YS5nZXREYXRhICkge1xuXG5cdFx0XHRyZXR1cm4gZS5jbGlwYm9hcmREYXRhLmdldERhdGEoICd0ZXh0L3BsYWluJyApO1xuXHRcdH1cblx0fVxuXG5cdC8qKlxuXHQgKiBQYXN0ZSBldmVudCBoaWdoZXIgb3JkZXIgZnVuY3Rpb24gZm9yIGNoYXJhY3RlcnMgbGltaXQuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjYuNy4xXG5cdCAqXG5cdCAqIEBwYXJhbSB7bnVtYmVyfSBsaW1pdCBNYXggYWxsb3dlZCBudW1iZXIgb2YgY2hhcmFjdGVycy5cblx0ICpcblx0ICogQHJldHVybnMge0Z1bmN0aW9ufSBFdmVudCBoYW5kbGVyLlxuXHQgKi9cblx0ZnVuY3Rpb24gcGFzdGVUZXh0KCBsaW1pdCApIHtcblxuXHRcdHJldHVybiBmdW5jdGlvbiggZSApIHtcblxuXHRcdFx0ZS5wcmV2ZW50RGVmYXVsdCgpO1xuXG5cdFx0XHR2YXIgcGFzdGVkVGV4dCA9IGdldFBhc3RlZFRleHQoIGUgKSxcblx0XHRcdFx0bmV3UG9zaXRpb24gPSB0aGlzLnNlbGVjdGlvblN0YXJ0ICsgcGFzdGVkVGV4dC5sZW5ndGgsXG5cdFx0XHRcdG5ld1RleHQgPSB0aGlzLnZhbHVlLnN1YnN0cmluZyggMCwgdGhpcy5zZWxlY3Rpb25TdGFydCApICsgcGFzdGVkVGV4dCArIHRoaXMudmFsdWUuc3Vic3RyaW5nKCB0aGlzLnNlbGVjdGlvblN0YXJ0ICk7XG5cblx0XHRcdHRoaXMudmFsdWUgPSBuZXdUZXh0LnN1YnN0cmluZyggMCwgbGltaXQgKTtcblx0XHRcdHRoaXMuc2V0U2VsZWN0aW9uUmFuZ2UoIG5ld1Bvc2l0aW9uLCBuZXdQb3NpdGlvbiApO1xuXHRcdH07XG5cdH1cblxuXHQvKipcblx0ICogTGltaXQgc3RyaW5nIGxlbmd0aCB0byBhIGNlcnRhaW4gbnVtYmVyIG9mIHdvcmRzLCBwcmVzZXJ2aW5nIGxpbmUgYnJlYWtzLlxuXHQgKlxuXHQgKiBAc2luY2UgMS42Ljhcblx0ICpcblx0ICogQHBhcmFtIHtzdHJpbmd9IHRleHQgIFRleHQuXG5cdCAqIEBwYXJhbSB7bnVtYmVyfSBsaW1pdCBNYXggYWxsb3dlZCBudW1iZXIgb2Ygd29yZHMuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtzdHJpbmd9IFRleHQgd2l0aCB0aGUgbGltaXRlZCBudW1iZXIgb2Ygd29yZHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBsaW1pdFdvcmRzKCB0ZXh0LCBsaW1pdCApIHtcblxuXHRcdHZhciBzZXBhcmF0b3JzLFxuXHRcdFx0bmV3VGV4dEFycmF5LFxuXHRcdFx0cmVzdWx0ID0gJyc7XG5cblx0XHQvLyBSZWd1bGFyIGV4cHJlc3Npb24gcGF0dGVybjogbWF0Y2ggYW55IHNwYWNlIGNoYXJhY3Rlci5cblx0XHR2YXIgcmVnRXggPSAvXFxzKy9nO1xuXG5cdFx0Ly8gU3RvcmUgc2VwYXJhdG9ycyBmb3IgZnVydGhlciBqb2luLlxuXHRcdHNlcGFyYXRvcnMgPSB0ZXh0LnRyaW0oKS5tYXRjaCggcmVnRXggKSB8fCBbXTtcblxuXHRcdC8vIFNwbGl0IHRoZSBuZXcgdGV4dCBieSByZWd1bGFyIGV4cHJlc3Npb24uXG5cdFx0bmV3VGV4dEFycmF5ID0gdGV4dC5zcGxpdCggcmVnRXggKTtcblxuXHRcdC8vIExpbWl0IHRoZSBudW1iZXIgb2Ygd29yZHMuXG5cdFx0bmV3VGV4dEFycmF5LnNwbGljZSggbGltaXQsIG5ld1RleHRBcnJheS5sZW5ndGggKTtcblxuXHRcdC8vIEpvaW4gdGhlIHdvcmRzIHRvZ2V0aGVyIHVzaW5nIHN0b3JlZCBzZXBhcmF0b3JzLlxuXHRcdGZvciAoIHZhciBpID0gMDsgaSA8IG5ld1RleHRBcnJheS5sZW5ndGg7IGkrKyApIHtcblx0XHRcdHJlc3VsdCArPSBuZXdUZXh0QXJyYXlbIGkgXSArICggc2VwYXJhdG9yc1sgaSBdIHx8ICcnICk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHJlc3VsdC50cmltKCk7XG5cdH1cblxuXHQvKipcblx0ICogUGFzdGUgZXZlbnQgaGlnaGVyIG9yZGVyIGZ1bmN0aW9uIGZvciB3b3JkcyBsaW1pdC5cblx0ICpcblx0ICogQHNpbmNlIDEuNS42XG5cdCAqXG5cdCAqIEBwYXJhbSB7bnVtYmVyfSBsaW1pdCBNYXggYWxsb3dlZCBudW1iZXIgb2Ygd29yZHMuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtGdW5jdGlvbn0gRXZlbnQgaGFuZGxlci5cblx0ICovXG5cdGZ1bmN0aW9uIHBhc3RlV29yZHMoIGxpbWl0ICkge1xuXG5cdFx0cmV0dXJuIGZ1bmN0aW9uKCBlICkge1xuXG5cdFx0XHRlLnByZXZlbnREZWZhdWx0KCk7XG5cblx0XHRcdHZhciBwYXN0ZWRUZXh0ID0gZ2V0UGFzdGVkVGV4dCggZSApLFxuXHRcdFx0XHRuZXdQb3NpdGlvbiA9IHRoaXMuc2VsZWN0aW9uU3RhcnQgKyBwYXN0ZWRUZXh0Lmxlbmd0aCxcblx0XHRcdFx0bmV3VGV4dCA9IHRoaXMudmFsdWUuc3Vic3RyaW5nKCAwLCB0aGlzLnNlbGVjdGlvblN0YXJ0ICkgKyBwYXN0ZWRUZXh0ICsgdGhpcy52YWx1ZS5zdWJzdHJpbmcoIHRoaXMuc2VsZWN0aW9uU3RhcnQgKTtcblxuXHRcdFx0dGhpcy52YWx1ZSA9IGxpbWl0V29yZHMoIG5ld1RleHQsIGxpbWl0ICk7XG5cdFx0XHR0aGlzLnNldFNlbGVjdGlvblJhbmdlKCBuZXdQb3NpdGlvbiwgbmV3UG9zaXRpb24gKTtcblx0XHR9O1xuXHR9XG5cblx0LyoqXG5cdCAqIEFycmF5LmZvcm0gcG9seWZpbGwuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjUuNlxuXHQgKlxuXHQgKiBAcGFyYW0ge29iamVjdH0gZWwgSXRlcmF0b3IuXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtvYmplY3R9IEFycmF5LlxuXHQgKi9cblx0ZnVuY3Rpb24gYXJyRnJvbSggZWwgKSB7XG5cblx0XHRyZXR1cm4gW10uc2xpY2UuY2FsbCggZWwgKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBET01Db250ZW50TG9hZGVkIGhhbmRsZXIuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjUuNlxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZHkoKSB7XG5cblx0XHRhcnJGcm9tKCBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCAnLndwZm9ybXMtbGltaXQtY2hhcmFjdGVycy1lbmFibGVkJyApIClcblx0XHRcdC5tYXAoXG5cdFx0XHRcdGZ1bmN0aW9uKCBlICkge1xuXG5cdFx0XHRcdFx0dmFyIGxpbWl0ID0gcGFyc2VJbnQoIGUuZGF0YXNldC50ZXh0TGltaXQsIDEwICkgfHwgMDtcblx0XHRcdFx0XHRlLnZhbHVlID0gZS52YWx1ZS5zbGljZSggMCwgbGltaXQgKTtcblx0XHRcdFx0XHR2YXIgaGludCA9IGNyZWF0ZUhpbnQoXG5cdFx0XHRcdFx0XHRlLmRhdGFzZXQuZm9ybUlkLFxuXHRcdFx0XHRcdFx0ZS5kYXRhc2V0LmZpZWxkSWQsXG5cdFx0XHRcdFx0XHRyZW5kZXJIaW50KFxuXHRcdFx0XHRcdFx0XHR3aW5kb3cud3Bmb3Jtc19zZXR0aW5ncy52YWxfbGltaXRfY2hhcmFjdGVycyxcblx0XHRcdFx0XHRcdFx0ZS52YWx1ZS5sZW5ndGgsXG5cdFx0XHRcdFx0XHRcdGxpbWl0XG5cdFx0XHRcdFx0XHQpXG5cdFx0XHRcdFx0KTtcblx0XHRcdFx0XHR2YXIgZm4gPSBjaGVja0NoYXJhY3RlcnMoIGhpbnQsIGxpbWl0ICk7XG5cdFx0XHRcdFx0ZS5wYXJlbnROb2RlLmFwcGVuZENoaWxkKCBoaW50ICk7XG5cblx0XHRcdFx0XHRlLmFkZEV2ZW50TGlzdGVuZXIoICdrZXlkb3duJywgZm4gKTtcblx0XHRcdFx0XHRlLmFkZEV2ZW50TGlzdGVuZXIoICdrZXl1cCcsIGZuICk7XG5cdFx0XHRcdFx0ZS5hZGRFdmVudExpc3RlbmVyKCAncGFzdGUnLCBwYXN0ZVRleHQoIGxpbWl0ICkgKTtcblx0XHRcdFx0fVxuXHRcdFx0KTtcblxuXHRcdGFyckZyb20oIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoICcud3Bmb3Jtcy1saW1pdC13b3Jkcy1lbmFibGVkJyApIClcblx0XHRcdC5tYXAoXG5cdFx0XHRcdGZ1bmN0aW9uKCBlICkge1xuXG5cdFx0XHRcdFx0dmFyIGxpbWl0ID0gcGFyc2VJbnQoIGUuZGF0YXNldC50ZXh0TGltaXQsIDEwICkgfHwgMDtcblxuXHRcdFx0XHRcdGUudmFsdWUgPSBsaW1pdFdvcmRzKCBlLnZhbHVlLCBsaW1pdCApO1xuXG5cdFx0XHRcdFx0dmFyIGhpbnQgPSBjcmVhdGVIaW50KFxuXHRcdFx0XHRcdFx0ZS5kYXRhc2V0LmZvcm1JZCxcblx0XHRcdFx0XHRcdGUuZGF0YXNldC5maWVsZElkLFxuXHRcdFx0XHRcdFx0cmVuZGVySGludChcblx0XHRcdFx0XHRcdFx0d2luZG93LndwZm9ybXNfc2V0dGluZ3MudmFsX2xpbWl0X3dvcmRzLFxuXHRcdFx0XHRcdFx0XHRjb3VudFdvcmRzKCBlLnZhbHVlLnRyaW0oKSApLFxuXHRcdFx0XHRcdFx0XHRsaW1pdFxuXHRcdFx0XHRcdFx0KVxuXHRcdFx0XHRcdCk7XG5cdFx0XHRcdFx0dmFyIGZuID0gY2hlY2tXb3JkcyggaGludCwgbGltaXQgKTtcblx0XHRcdFx0XHRlLnBhcmVudE5vZGUuYXBwZW5kQ2hpbGQoIGhpbnQgKTtcblxuXHRcdFx0XHRcdGUuYWRkRXZlbnRMaXN0ZW5lciggJ2tleWRvd24nLCBmbiApO1xuXHRcdFx0XHRcdGUuYWRkRXZlbnRMaXN0ZW5lciggJ2tleXVwJywgZm4gKTtcblx0XHRcdFx0XHRlLmFkZEV2ZW50TGlzdGVuZXIoICdwYXN0ZScsIHBhc3RlV29yZHMoIGxpbWl0ICkgKTtcblx0XHRcdFx0fVxuXHRcdFx0KTtcblx0fVxuXG5cdGlmICggZG9jdW1lbnQucmVhZHlTdGF0ZSA9PT0gJ2xvYWRpbmcnICkge1xuXHRcdGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoICdET01Db250ZW50TG9hZGVkJywgcmVhZHkgKTtcblx0fSBlbHNlIHtcblx0XHRyZWFkeSgpO1xuXHR9XG5cbn0oKSApO1xuIl0sIm1hcHBpbmdzIjoiQUFBQSxZQUFZOztBQUVWLGFBQVc7RUFFWjtBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7RUFDQyxTQUFTQSxVQUFVLENBQUVDLFFBQVEsRUFBRUMsS0FBSyxFQUFFQyxLQUFLLEVBQUc7SUFFN0MsT0FBT0YsUUFBUSxDQUFDRyxPQUFPLENBQUUsU0FBUyxFQUFFRixLQUFLLENBQUUsQ0FBQ0UsT0FBTyxDQUFFLFNBQVMsRUFBRUQsS0FBSyxDQUFFLENBQUNDLE9BQU8sQ0FBRSxhQUFhLEVBQUVELEtBQUssR0FBR0QsS0FBSyxDQUFFO0VBQ2hIOztFQUVBO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FB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
},{}]},{},[1])