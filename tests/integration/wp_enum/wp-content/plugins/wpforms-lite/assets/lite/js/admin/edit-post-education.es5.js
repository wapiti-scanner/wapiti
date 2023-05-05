(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/* global wpforms_edit_post_education */

/**
 * WPForms Edit Post Education function.
 *
 * @since 1.8.1
 */

'use strict';

function _slicedToArray(arr, i) { return _arrayWithHoles(arr) || _iterableToArrayLimit(arr, i) || _unsupportedIterableToArray(arr, i) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }
function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i]; return arr2; }
function _iterableToArrayLimit(arr, i) { var _i = null == arr ? null : "undefined" != typeof Symbol && arr[Symbol.iterator] || arr["@@iterator"]; if (null != _i) { var _s, _e, _x, _r, _arr = [], _n = !0, _d = !1; try { if (_x = (_i = _i.call(arr)).next, 0 === i) { if (Object(_i) !== _i) return; _n = !1; } else for (; !(_n = (_s = _x.call(_i)).done) && (_arr.push(_s.value), _arr.length !== i); _n = !0); } catch (err) { _d = !0, _e = err; } finally { try { if (!_n && null != _i.return && (_r = _i.return(), Object(_r) !== _r)) return; } finally { if (_d) throw _e; } } return _arr; } }
function _arrayWithHoles(arr) { if (Array.isArray(arr)) return arr; }
var WPFormsEditPostEducation = window.WPFormsEditPostEducation || function (document, window, $) {
  /**
   * Public functions and properties.
   *
   * @since 1.8.1
   *
   * @type {object}
   */
  var app = {
    /**
     * Determine if the notice was showed before.
     *
     * @since 1.8.1
     */
    isNoticeVisible: false,
    /**
     * Start the engine.
     *
     * @since 1.8.1
     */
    init: function init() {
      $(window).on('load', function () {
        // In the case of jQuery 3.+, we need to wait for a ready event first.
        if (typeof $.ready.then === 'function') {
          $.ready.then(app.load);
        } else {
          app.load();
        }
      });
    },
    /**
     * Page load.
     *
     * @since 1.8.1
     */
    load: function load() {
      if (!app.isGutenbergEditor()) {
        app.maybeShowClassicNotice();
        app.bindClassicEvents();
        return;
      }
      var blockLoadedInterval = setInterval(function () {
        if (!document.querySelector('.editor-post-title__input, iframe[name="editor-canvas"]')) {
          return;
        }
        clearInterval(blockLoadedInterval);
        if (!app.isFse()) {
          app.maybeShowGutenbergNotice();
          app.bindGutenbergEvents();
          return;
        }
        var iframe = document.querySelector('iframe[name="editor-canvas"]');
        var observer = new MutationObserver(function () {
          var iframeDocument = iframe.contentDocument || iframe.contentWindow.document || {};
          if (iframeDocument.readyState === 'complete' && iframeDocument.querySelector('.editor-post-title__input')) {
            app.maybeShowGutenbergNotice();
            app.bindFseEvents();
            observer.disconnect();
          }
        });
        observer.observe(document.body, {
          subtree: true,
          childList: true
        });
      }, 200);
    },
    /**
     * Bind events for Classic Editor.
     *
     * @since 1.8.1
     */
    bindClassicEvents: function bindClassicEvents() {
      var $document = $(document);
      if (!app.isNoticeVisible) {
        $document.on('input', '#title', app.maybeShowClassicNotice);
      }
      $document.on('click', '.wpforms-edit-post-education-notice-close', app.closeNotice);
    },
    /**
     * Bind events for Gutenberg Editor.
     *
     * @since 1.8.1
     */
    bindGutenbergEvents: function bindGutenbergEvents() {
      var $document = $(document);
      $document.on('DOMSubtreeModified', '.edit-post-layout', app.distractionFreeModeToggle);
      if (app.isNoticeVisible) {
        return;
      }
      $document.on('input', '.editor-post-title__input', app.maybeShowGutenbergNotice).on('DOMSubtreeModified', '.editor-post-title__input', app.maybeShowGutenbergNotice);
    },
    /**
     * Bind events for Gutenberg Editor in FSE mode.
     *
     * @since 1.8.1
     */
    bindFseEvents: function bindFseEvents() {
      var $iframe = $('iframe[name="editor-canvas"]');
      $(document).on('DOMSubtreeModified', '.edit-post-layout', app.distractionFreeModeToggle);
      $iframe.contents().on('DOMSubtreeModified', '.editor-post-title__input', app.maybeShowGutenbergNotice);
    },
    /**
     * Determine if the editor is Gutenberg.
     *
     * @since 1.8.1
     *
     * @returns {boolean} True if the editor is Gutenberg.
     */
    isGutenbergEditor: function isGutenbergEditor() {
      return typeof wp !== 'undefined' && typeof wp.blocks !== 'undefined';
    },
    /**
     * Determine if the editor is Gutenberg in FSE mode.
     *
     * @since 1.8.1
     *
     * @returns {boolean} True if the Gutenberg editor in FSE mode.
     */
    isFse: function isFse() {
      return Boolean($('iframe[name="editor-canvas"]').length);
    },
    /**
     * Create a notice for Gutenberg.
     *
     * @since 1.8.1
     */
    showGutenbergNotice: function showGutenbergNotice() {
      wp.data.dispatch('core/notices').createInfoNotice(wpforms_edit_post_education.gutenberg_notice.template, app.getGutenbergNoticeSettings());

      // The notice component doesn't have a way to add HTML id or class to the notice.
      // Also, the notice became visible with a delay on old Gutenberg versions.
      var hasNotice = setInterval(function () {
        var noticeBody = $('.wpforms-edit-post-education-notice-body');
        if (!noticeBody.length) {
          return;
        }
        var $notice = noticeBody.closest('.components-notice');
        $notice.addClass('wpforms-edit-post-education-notice');
        $notice.find('.is-secondary, .is-link').removeClass('is-secondary').removeClass('is-link').addClass('is-primary');
        clearInterval(hasNotice);
      }, 100);
    },
    /**
     * Get settings for the Gutenberg notice.
     *
     * @since 1.8.1
     *
     * @returns {object} Notice settings.
     */
    getGutenbergNoticeSettings: function getGutenbergNoticeSettings() {
      var pluginName = 'wpforms-edit-post-product-education-guide';
      var noticeSettings = {
        id: pluginName,
        isDismissible: true,
        HTML: true,
        __unstableHTML: true,
        actions: [{
          className: 'wpforms-edit-post-education-notice-guide-button',
          variant: 'primary',
          label: wpforms_edit_post_education.gutenberg_notice.button
        }]
      };
      if (!wpforms_edit_post_education.gutenberg_guide) {
        noticeSettings.actions[0].url = wpforms_edit_post_education.gutenberg_notice.url;
        return noticeSettings;
      }
      var Guide = wp.components.Guide;
      var useState = wp.element.useState;
      var registerPlugin = wp.plugins.registerPlugin;
      var unregisterPlugin = wp.plugins.unregisterPlugin;
      var GutenbergTutorial = function GutenbergTutorial() {
        var _useState = useState(true),
          _useState2 = _slicedToArray(_useState, 2),
          isOpen = _useState2[0],
          setIsOpen = _useState2[1];
        if (!isOpen) {
          return null;
        }
        return (
          /*#__PURE__*/
          // eslint-disable-next-line react/react-in-jsx-scope
          React.createElement(Guide, {
            className: "edit-post-welcome-guide",
            onFinish: function onFinish() {
              unregisterPlugin(pluginName);
              setIsOpen(false);
            },
            pages: app.getGuidePages()
          })
        );
      };
      noticeSettings.onDismiss = app.updateUserMeta;
      noticeSettings.actions[0].onClick = function () {
        return registerPlugin(pluginName, {
          render: GutenbergTutorial
        });
      };
      return noticeSettings;
    },
    /**
     * Get Guide pages in proper format.
     *
     * @since 1.8.1
     *
     * @returns {Array} Guide Pages.
     */
    getGuidePages: function getGuidePages() {
      var pages = [];
      wpforms_edit_post_education.gutenberg_guide.forEach(function (page) {
        pages.push({
          /* eslint-disable react/react-in-jsx-scope */
          content: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("h1", {
            className: "edit-post-welcome-guide__heading"
          }, page.title), /*#__PURE__*/React.createElement("p", {
            className: "edit-post-welcome-guide__text"
          }, page.content)),
          image: /*#__PURE__*/React.createElement("img", {
            className: "edit-post-welcome-guide__image",
            src: page.image,
            alt: page.title
          })
          /* eslint-enable react/react-in-jsx-scope */
        });
      });

      return pages;
    },
    /**
     * Show notice if the page title matches some keywords for Classic Editor.
     *
     * @since 1.8.1
     */
    maybeShowClassicNotice: function maybeShowClassicNotice() {
      if (app.isNoticeVisible) {
        return;
      }
      if (app.isTitleMatchKeywords($('#title').val())) {
        app.isNoticeVisible = true;
        $('.wpforms-edit-post-education-notice').removeClass('wpforms-hidden');
      }
    },
    /**
     * Show notice if the page title matches some keywords for Gutenberg Editor.
     *
     * @since 1.8.1
     */
    maybeShowGutenbergNotice: function maybeShowGutenbergNotice() {
      if (app.isNoticeVisible) {
        return;
      }
      var $postTitle = app.isFse() ? $('iframe[name="editor-canvas"]').contents().find('.editor-post-title__input') : $('.editor-post-title__input');
      var tagName = $postTitle.prop('tagName');
      var title = tagName === 'TEXTAREA' ? $postTitle.val() : $postTitle.text();
      if (app.isTitleMatchKeywords(title)) {
        app.isNoticeVisible = true;
        app.showGutenbergNotice();
      }
    },
    /**
     * Add notice class when the distraction mode is enabled.
     *
     * @since 1.8.1.2
     */
    distractionFreeModeToggle: function distractionFreeModeToggle() {
      if (!app.isNoticeVisible) {
        return;
      }
      var $document = $(document);
      var isDistractionFreeMode = Boolean($document.find('.is-distraction-free').length);
      if (!isDistractionFreeMode) {
        return;
      }
      var isNoticeHasClass = Boolean($('.wpforms-edit-post-education-notice').length);
      if (isNoticeHasClass) {
        return;
      }
      var $noticeBody = $document.find('.wpforms-edit-post-education-notice-body');
      var $notice = $noticeBody.closest('.components-notice');
      $notice.addClass('wpforms-edit-post-education-notice');
    },
    /**
     * Determine if the title matches keywords.
     *
     * @since 1.8.1
     *
     * @param {string} titleValue Page title value.
     *
     * @returns {boolean} True if the title matches some keywords.
     */
    isTitleMatchKeywords: function isTitleMatchKeywords(titleValue) {
      var expectedTitleRegex = new RegExp(/\b(contact|form)\b/i);
      return expectedTitleRegex.test(titleValue);
    },
    /**
     * Close a notice.
     *
     * @since 1.8.1
     */
    closeNotice: function closeNotice() {
      $(this).closest('.wpforms-edit-post-education-notice').remove();
      app.updateUserMeta();
    },
    /**
     * Update user meta and don't show the notice next time.
     *
     * @since 1.8.1
     */
    updateUserMeta: function updateUserMeta() {
      $.post(wpforms_edit_post_education.ajax_url, {
        action: 'wpforms_education_dismiss',
        nonce: wpforms_edit_post_education.education_nonce,
        section: 'edit-post-notice'
      });
    }
  };
  return app;
}(document, window, jQuery);
WPFormsEditPostEducation.init();
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJXUEZvcm1zRWRpdFBvc3RFZHVjYXRpb24iLCJ3aW5kb3ciLCJkb2N1bWVudCIsIiQiLCJhcHAiLCJpc05vdGljZVZpc2libGUiLCJpbml0Iiwib24iLCJyZWFkeSIsInRoZW4iLCJsb2FkIiwiaXNHdXRlbmJlcmdFZGl0b3IiLCJtYXliZVNob3dDbGFzc2ljTm90aWNlIiwiYmluZENsYXNzaWNFdmVudHMiLCJibG9ja0xvYWRlZEludGVydmFsIiwic2V0SW50ZXJ2YWwiLCJxdWVyeVNlbGVjdG9yIiwiY2xlYXJJbnRlcnZhbCIsImlzRnNlIiwibWF5YmVTaG93R3V0ZW5iZXJnTm90aWNlIiwiYmluZEd1dGVuYmVyZ0V2ZW50cyIsImlmcmFtZSIsIm9ic2VydmVyIiwiTXV0YXRpb25PYnNlcnZlciIsImlmcmFtZURvY3VtZW50IiwiY29udGVudERvY3VtZW50IiwiY29udGVudFdpbmRvdyIsInJlYWR5U3RhdGUiLCJiaW5kRnNlRXZlbnRzIiwiZGlzY29ubmVjdCIsIm9ic2VydmUiLCJib2R5Iiwic3VidHJlZSIsImNoaWxkTGlzdCIsIiRkb2N1bWVudCIsImNsb3NlTm90aWNlIiwiZGlzdHJhY3Rpb25GcmVlTW9kZVRvZ2dsZSIsIiRpZnJhbWUiLCJjb250ZW50cyIsIndwIiwiYmxvY2tzIiwiQm9vbGVhbiIsImxlbmd0aCIsInNob3dHdXRlbmJlcmdOb3RpY2UiLCJkYXRhIiwiZGlzcGF0Y2giLCJjcmVhdGVJbmZvTm90aWNlIiwid3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uIiwiZ3V0ZW5iZXJnX25vdGljZSIsInRlbXBsYXRlIiwiZ2V0R3V0ZW5iZXJnTm90aWNlU2V0dGluZ3MiLCJoYXNOb3RpY2UiLCJub3RpY2VCb2R5IiwiJG5vdGljZSIsImNsb3Nlc3QiLCJhZGRDbGFzcyIsImZpbmQiLCJyZW1vdmVDbGFzcyIsInBsdWdpbk5hbWUiLCJub3RpY2VTZXR0aW5ncyIsImlkIiwiaXNEaXNtaXNzaWJsZSIsIkhUTUwiLCJfX3Vuc3RhYmxlSFRNTCIsImFjdGlvbnMiLCJjbGFzc05hbWUiLCJ2YXJpYW50IiwibGFiZWwiLCJidXR0b24iLCJndXRlbmJlcmdfZ3VpZGUiLCJ1cmwiLCJHdWlkZSIsImNvbXBvbmVudHMiLCJ1c2VTdGF0ZSIsImVsZW1lbnQiLCJyZWdpc3RlclBsdWdpbiIsInBsdWdpbnMiLCJ1bnJlZ2lzdGVyUGx1Z2luIiwiR3V0ZW5iZXJnVHV0b3JpYWwiLCJpc09wZW4iLCJzZXRJc09wZW4iLCJnZXRHdWlkZVBhZ2VzIiwib25EaXNtaXNzIiwidXBkYXRlVXNlck1ldGEiLCJvbkNsaWNrIiwicmVuZGVyIiwicGFnZXMiLCJmb3JFYWNoIiwicGFnZSIsInB1c2giLCJjb250ZW50IiwidGl0bGUiLCJpbWFnZSIsImlzVGl0bGVNYXRjaEtleXdvcmRzIiwidmFsIiwiJHBvc3RUaXRsZSIsInRhZ05hbWUiLCJwcm9wIiwidGV4dCIsImlzRGlzdHJhY3Rpb25GcmVlTW9kZSIsImlzTm90aWNlSGFzQ2xhc3MiLCIkbm90aWNlQm9keSIsInRpdGxlVmFsdWUiLCJleHBlY3RlZFRpdGxlUmVnZXgiLCJSZWdFeHAiLCJ0ZXN0IiwicmVtb3ZlIiwicG9zdCIsImFqYXhfdXJsIiwiYWN0aW9uIiwibm9uY2UiLCJlZHVjYXRpb25fbm9uY2UiLCJzZWN0aW9uIiwialF1ZXJ5Il0sInNvdXJjZXMiOlsiZmFrZV82YWFiN2M5My5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKiBnbG9iYWwgd3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uICovXG5cbi8qKlxuICogV1BGb3JtcyBFZGl0IFBvc3QgRWR1Y2F0aW9uIGZ1bmN0aW9uLlxuICpcbiAqIEBzaW5jZSAxLjguMVxuICovXG5cbid1c2Ugc3RyaWN0JztcblxuY29uc3QgV1BGb3Jtc0VkaXRQb3N0RWR1Y2F0aW9uID0gd2luZG93LldQRm9ybXNFZGl0UG9zdEVkdWNhdGlvbiB8fCAoIGZ1bmN0aW9uKCBkb2N1bWVudCwgd2luZG93LCAkICkge1xuXG5cdC8qKlxuXHQgKiBQdWJsaWMgZnVuY3Rpb25zIGFuZCBwcm9wZXJ0aWVzLlxuXHQgKlxuXHQgKiBAc2luY2UgMS44LjFcblx0ICpcblx0ICogQHR5cGUge29iamVjdH1cblx0ICovXG5cdGNvbnN0IGFwcCA9IHtcblxuXHRcdC8qKlxuXHRcdCAqIERldGVybWluZSBpZiB0aGUgbm90aWNlIHdhcyBzaG93ZWQgYmVmb3JlLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICovXG5cdFx0aXNOb3RpY2VWaXNpYmxlOiBmYWxzZSxcblxuXHRcdC8qKlxuXHRcdCAqIFN0YXJ0IHRoZSBlbmdpbmUuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHRpbml0OiBmdW5jdGlvbigpIHtcblxuXHRcdFx0JCggd2luZG93ICkub24oICdsb2FkJywgZnVuY3Rpb24oKSB7XG5cblx0XHRcdFx0Ly8gSW4gdGhlIGNhc2Ugb2YgalF1ZXJ5IDMuKywgd2UgbmVlZCB0byB3YWl0IGZvciBhIHJlYWR5IGV2ZW50IGZpcnN0LlxuXHRcdFx0XHRpZiAoIHR5cGVvZiAkLnJlYWR5LnRoZW4gPT09ICdmdW5jdGlvbicgKSB7XG5cdFx0XHRcdFx0JC5yZWFkeS50aGVuKCBhcHAubG9hZCApO1xuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdGFwcC5sb2FkKCk7XG5cdFx0XHRcdH1cblx0XHRcdH0gKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogUGFnZSBsb2FkLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICovXG5cdFx0bG9hZDogZnVuY3Rpb24oKSB7XG5cblx0XHRcdGlmICggISBhcHAuaXNHdXRlbmJlcmdFZGl0b3IoKSApIHtcblx0XHRcdFx0YXBwLm1heWJlU2hvd0NsYXNzaWNOb3RpY2UoKTtcblx0XHRcdFx0YXBwLmJpbmRDbGFzc2ljRXZlbnRzKCk7XG5cblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHRjb25zdCBibG9ja0xvYWRlZEludGVydmFsID0gc2V0SW50ZXJ2YWwoIGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRcdGlmICggISBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCAnLmVkaXRvci1wb3N0LXRpdGxlX19pbnB1dCwgaWZyYW1lW25hbWU9XCJlZGl0b3ItY2FudmFzXCJdJyApICkge1xuXHRcdFx0XHRcdHJldHVybjtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGNsZWFySW50ZXJ2YWwoIGJsb2NrTG9hZGVkSW50ZXJ2YWwgKTtcblxuXHRcdFx0XHRpZiAoICEgYXBwLmlzRnNlKCkgKSB7XG5cblx0XHRcdFx0XHRhcHAubWF5YmVTaG93R3V0ZW5iZXJnTm90aWNlKCk7XG5cdFx0XHRcdFx0YXBwLmJpbmRHdXRlbmJlcmdFdmVudHMoKTtcblxuXHRcdFx0XHRcdHJldHVybjtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoICdpZnJhbWVbbmFtZT1cImVkaXRvci1jYW52YXNcIl0nICk7XG5cdFx0XHRcdGNvbnN0IG9ic2VydmVyID0gbmV3IE11dGF0aW9uT2JzZXJ2ZXIoIGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRcdFx0Y29uc3QgaWZyYW1lRG9jdW1lbnQgPSBpZnJhbWUuY29udGVudERvY3VtZW50IHx8IGlmcmFtZS5jb250ZW50V2luZG93LmRvY3VtZW50IHx8IHt9O1xuXG5cdFx0XHRcdFx0aWYgKCBpZnJhbWVEb2N1bWVudC5yZWFkeVN0YXRlID09PSAnY29tcGxldGUnICYmIGlmcmFtZURvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoICcuZWRpdG9yLXBvc3QtdGl0bGVfX2lucHV0JyApICkge1xuXHRcdFx0XHRcdFx0YXBwLm1heWJlU2hvd0d1dGVuYmVyZ05vdGljZSgpO1xuXHRcdFx0XHRcdFx0YXBwLmJpbmRGc2VFdmVudHMoKTtcblxuXHRcdFx0XHRcdFx0b2JzZXJ2ZXIuZGlzY29ubmVjdCgpO1xuXHRcdFx0XHRcdH1cblx0XHRcdFx0fSApO1xuXHRcdFx0XHRvYnNlcnZlci5vYnNlcnZlKCBkb2N1bWVudC5ib2R5LCB7IHN1YnRyZWU6IHRydWUsIGNoaWxkTGlzdDogdHJ1ZSB9ICk7XG5cdFx0XHR9LCAyMDAgKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogQmluZCBldmVudHMgZm9yIENsYXNzaWMgRWRpdG9yLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICovXG5cdFx0YmluZENsYXNzaWNFdmVudHM6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRjb25zdCAkZG9jdW1lbnQgPSAkKCBkb2N1bWVudCApO1xuXG5cdFx0XHRpZiAoICEgYXBwLmlzTm90aWNlVmlzaWJsZSApIHtcblx0XHRcdFx0JGRvY3VtZW50Lm9uKCAnaW5wdXQnLCAnI3RpdGxlJywgYXBwLm1heWJlU2hvd0NsYXNzaWNOb3RpY2UgKTtcblx0XHRcdH1cblxuXHRcdFx0JGRvY3VtZW50Lm9uKCAnY2xpY2snLCAnLndwZm9ybXMtZWRpdC1wb3N0LWVkdWNhdGlvbi1ub3RpY2UtY2xvc2UnLCBhcHAuY2xvc2VOb3RpY2UgKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogQmluZCBldmVudHMgZm9yIEd1dGVuYmVyZyBFZGl0b3IuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHRiaW5kR3V0ZW5iZXJnRXZlbnRzOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0Y29uc3QgJGRvY3VtZW50ID0gJCggZG9jdW1lbnQgKTtcblxuXHRcdFx0JGRvY3VtZW50XG5cdFx0XHRcdC5vbiggJ0RPTVN1YnRyZWVNb2RpZmllZCcsICcuZWRpdC1wb3N0LWxheW91dCcsIGFwcC5kaXN0cmFjdGlvbkZyZWVNb2RlVG9nZ2xlICk7XG5cblx0XHRcdGlmICggYXBwLmlzTm90aWNlVmlzaWJsZSApIHtcblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHQkZG9jdW1lbnRcblx0XHRcdFx0Lm9uKCAnaW5wdXQnLCAnLmVkaXRvci1wb3N0LXRpdGxlX19pbnB1dCcsIGFwcC5tYXliZVNob3dHdXRlbmJlcmdOb3RpY2UgKVxuXHRcdFx0XHQub24oICdET01TdWJ0cmVlTW9kaWZpZWQnLCAnLmVkaXRvci1wb3N0LXRpdGxlX19pbnB1dCcsIGFwcC5tYXliZVNob3dHdXRlbmJlcmdOb3RpY2UgKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogQmluZCBldmVudHMgZm9yIEd1dGVuYmVyZyBFZGl0b3IgaW4gRlNFIG1vZGUuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHRiaW5kRnNlRXZlbnRzOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0Y29uc3QgJGlmcmFtZSA9ICQoICdpZnJhbWVbbmFtZT1cImVkaXRvci1jYW52YXNcIl0nICk7XG5cblx0XHRcdCQoIGRvY3VtZW50IClcblx0XHRcdFx0Lm9uKCAnRE9NU3VidHJlZU1vZGlmaWVkJywgJy5lZGl0LXBvc3QtbGF5b3V0JywgYXBwLmRpc3RyYWN0aW9uRnJlZU1vZGVUb2dnbGUgKTtcblxuXHRcdFx0JGlmcmFtZS5jb250ZW50cygpXG5cdFx0XHRcdC5vbiggJ0RPTVN1YnRyZWVNb2RpZmllZCcsICcuZWRpdG9yLXBvc3QtdGl0bGVfX2lucHV0JywgYXBwLm1heWJlU2hvd0d1dGVuYmVyZ05vdGljZSApO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBEZXRlcm1pbmUgaWYgdGhlIGVkaXRvciBpcyBHdXRlbmJlcmcuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKlxuXHRcdCAqIEByZXR1cm5zIHtib29sZWFufSBUcnVlIGlmIHRoZSBlZGl0b3IgaXMgR3V0ZW5iZXJnLlxuXHRcdCAqL1xuXHRcdGlzR3V0ZW5iZXJnRWRpdG9yOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0cmV0dXJuIHR5cGVvZiB3cCAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdwLmJsb2NrcyAhPT0gJ3VuZGVmaW5lZCc7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIERldGVybWluZSBpZiB0aGUgZWRpdG9yIGlzIEd1dGVuYmVyZyBpbiBGU0UgbW9kZS5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHJldHVybnMge2Jvb2xlYW59IFRydWUgaWYgdGhlIEd1dGVuYmVyZyBlZGl0b3IgaW4gRlNFIG1vZGUuXG5cdFx0ICovXG5cdFx0aXNGc2U6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRyZXR1cm4gQm9vbGVhbiggJCggJ2lmcmFtZVtuYW1lPVwiZWRpdG9yLWNhbnZhc1wiXScgKS5sZW5ndGggKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogQ3JlYXRlIGEgbm90aWNlIGZvciBHdXRlbmJlcmcuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHRzaG93R3V0ZW5iZXJnTm90aWNlOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0d3AuZGF0YS5kaXNwYXRjaCggJ2NvcmUvbm90aWNlcycgKS5jcmVhdGVJbmZvTm90aWNlKFxuXHRcdFx0XHR3cGZvcm1zX2VkaXRfcG9zdF9lZHVjYXRpb24uZ3V0ZW5iZXJnX25vdGljZS50ZW1wbGF0ZSxcblx0XHRcdFx0YXBwLmdldEd1dGVuYmVyZ05vdGljZVNldHRpbmdzKClcblx0XHRcdCk7XG5cblx0XHRcdC8vIFRoZSBub3RpY2UgY29tcG9uZW50IGRvZXNuJ3QgaGF2ZSBhIHdheSB0byBhZGQgSFRNTCBpZCBvciBjbGFzcyB0byB0aGUgbm90aWNlLlxuXHRcdFx0Ly8gQWxzbywgdGhlIG5vdGljZSBiZWNhbWUgdmlzaWJsZSB3aXRoIGEgZGVsYXkgb24gb2xkIEd1dGVuYmVyZyB2ZXJzaW9ucy5cblx0XHRcdGNvbnN0IGhhc05vdGljZSA9IHNldEludGVydmFsKCBmdW5jdGlvbigpIHtcblxuXHRcdFx0XHRjb25zdCBub3RpY2VCb2R5ID0gJCggJy53cGZvcm1zLWVkaXQtcG9zdC1lZHVjYXRpb24tbm90aWNlLWJvZHknICk7XG5cdFx0XHRcdGlmICggISBub3RpY2VCb2R5Lmxlbmd0aCApIHtcblx0XHRcdFx0XHRyZXR1cm47XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRjb25zdCAkbm90aWNlID0gbm90aWNlQm9keS5jbG9zZXN0KCAnLmNvbXBvbmVudHMtbm90aWNlJyApO1xuXHRcdFx0XHQkbm90aWNlLmFkZENsYXNzKCAnd3Bmb3Jtcy1lZGl0LXBvc3QtZWR1Y2F0aW9uLW5vdGljZScgKTtcblx0XHRcdFx0JG5vdGljZS5maW5kKCAnLmlzLXNlY29uZGFyeSwgLmlzLWxpbmsnICkucmVtb3ZlQ2xhc3MoICdpcy1zZWNvbmRhcnknICkucmVtb3ZlQ2xhc3MoICdpcy1saW5rJyApLmFkZENsYXNzKCAnaXMtcHJpbWFyeScgKTtcblxuXHRcdFx0XHRjbGVhckludGVydmFsKCBoYXNOb3RpY2UgKTtcblx0XHRcdH0sIDEwMCApO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBHZXQgc2V0dGluZ3MgZm9yIHRoZSBHdXRlbmJlcmcgbm90aWNlLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7b2JqZWN0fSBOb3RpY2Ugc2V0dGluZ3MuXG5cdFx0ICovXG5cdFx0Z2V0R3V0ZW5iZXJnTm90aWNlU2V0dGluZ3M6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRjb25zdCBwbHVnaW5OYW1lID0gJ3dwZm9ybXMtZWRpdC1wb3N0LXByb2R1Y3QtZWR1Y2F0aW9uLWd1aWRlJztcblx0XHRcdGNvbnN0IG5vdGljZVNldHRpbmdzID0ge1xuXHRcdFx0XHRpZDogcGx1Z2luTmFtZSxcblx0XHRcdFx0aXNEaXNtaXNzaWJsZTogdHJ1ZSxcblx0XHRcdFx0SFRNTDogdHJ1ZSxcblx0XHRcdFx0X191bnN0YWJsZUhUTUw6IHRydWUsXG5cdFx0XHRcdGFjdGlvbnM6IFtcblx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRjbGFzc05hbWU6ICd3cGZvcm1zLWVkaXQtcG9zdC1lZHVjYXRpb24tbm90aWNlLWd1aWRlLWJ1dHRvbicsXG5cdFx0XHRcdFx0XHR2YXJpYW50OiAncHJpbWFyeScsXG5cdFx0XHRcdFx0XHRsYWJlbDogd3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uLmd1dGVuYmVyZ19ub3RpY2UuYnV0dG9uLFxuXHRcdFx0XHRcdH0sXG5cdFx0XHRcdF0sXG5cdFx0XHR9O1xuXG5cdFx0XHRpZiAoICEgd3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uLmd1dGVuYmVyZ19ndWlkZSApIHtcblxuXHRcdFx0XHRub3RpY2VTZXR0aW5ncy5hY3Rpb25zWzBdLnVybCA9IHdwZm9ybXNfZWRpdF9wb3N0X2VkdWNhdGlvbi5ndXRlbmJlcmdfbm90aWNlLnVybDtcblxuXHRcdFx0XHRyZXR1cm4gbm90aWNlU2V0dGluZ3M7XG5cdFx0XHR9XG5cblx0XHRcdGNvbnN0IEd1aWRlID0gd3AuY29tcG9uZW50cy5HdWlkZTtcblx0XHRcdGNvbnN0IHVzZVN0YXRlID0gd3AuZWxlbWVudC51c2VTdGF0ZTtcblx0XHRcdGNvbnN0IHJlZ2lzdGVyUGx1Z2luID0gd3AucGx1Z2lucy5yZWdpc3RlclBsdWdpbjtcblx0XHRcdGNvbnN0IHVucmVnaXN0ZXJQbHVnaW4gPSB3cC5wbHVnaW5zLnVucmVnaXN0ZXJQbHVnaW47XG5cdFx0XHRjb25zdCBHdXRlbmJlcmdUdXRvcmlhbCA9IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRcdGNvbnN0IFsgaXNPcGVuLCBzZXRJc09wZW4gXSA9IHVzZVN0YXRlKCB0cnVlICk7XG5cblx0XHRcdFx0aWYgKCAhIGlzT3BlbiApIHtcblx0XHRcdFx0XHRyZXR1cm4gbnVsbDtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHJldHVybiAoXG5cdFx0XHRcdFx0Ly8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIHJlYWN0L3JlYWN0LWluLWpzeC1zY29wZVxuXHRcdFx0XHRcdDxHdWlkZVxuXHRcdFx0XHRcdFx0Y2xhc3NOYW1lPVwiZWRpdC1wb3N0LXdlbGNvbWUtZ3VpZGVcIlxuXHRcdFx0XHRcdFx0b25GaW5pc2g9eyAoKSA9PiB7XG5cdFx0XHRcdFx0XHRcdHVucmVnaXN0ZXJQbHVnaW4oIHBsdWdpbk5hbWUgKTtcblx0XHRcdFx0XHRcdFx0c2V0SXNPcGVuKCBmYWxzZSApO1xuXHRcdFx0XHRcdFx0fSB9XG5cdFx0XHRcdFx0XHRwYWdlcz17IGFwcC5nZXRHdWlkZVBhZ2VzKCkgfVxuXHRcdFx0XHRcdC8+XG5cdFx0XHRcdCk7XG5cdFx0XHR9O1xuXG5cdFx0XHRub3RpY2VTZXR0aW5ncy5vbkRpc21pc3MgPSBhcHAudXBkYXRlVXNlck1ldGE7XG5cdFx0XHRub3RpY2VTZXR0aW5ncy5hY3Rpb25zWzBdLm9uQ2xpY2sgPSAoKSA9PiByZWdpc3RlclBsdWdpbiggcGx1Z2luTmFtZSwgeyByZW5kZXI6IEd1dGVuYmVyZ1R1dG9yaWFsIH0gKTtcblxuXHRcdFx0cmV0dXJuIG5vdGljZVNldHRpbmdzO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBHZXQgR3VpZGUgcGFnZXMgaW4gcHJvcGVyIGZvcm1hdC5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHJldHVybnMge0FycmF5fSBHdWlkZSBQYWdlcy5cblx0XHQgKi9cblx0XHRnZXRHdWlkZVBhZ2VzOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0Y29uc3QgcGFnZXMgPSBbXTtcblxuXHRcdFx0d3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uLmd1dGVuYmVyZ19ndWlkZS5mb3JFYWNoKCBmdW5jdGlvbiggcGFnZSApIHtcblx0XHRcdFx0cGFnZXMucHVzaChcblx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHQvKiBlc2xpbnQtZGlzYWJsZSByZWFjdC9yZWFjdC1pbi1qc3gtc2NvcGUgKi9cblx0XHRcdFx0XHRcdGNvbnRlbnQ6IChcblx0XHRcdFx0XHRcdFx0PD5cblx0XHRcdFx0XHRcdFx0XHQ8aDEgY2xhc3NOYW1lPVwiZWRpdC1wb3N0LXdlbGNvbWUtZ3VpZGVfX2hlYWRpbmdcIj57IHBhZ2UudGl0bGUgfTwvaDE+XG5cdFx0XHRcdFx0XHRcdFx0PHAgY2xhc3NOYW1lPVwiZWRpdC1wb3N0LXdlbGNvbWUtZ3VpZGVfX3RleHRcIj57IHBhZ2UuY29udGVudCB9PC9wPlxuXHRcdFx0XHRcdFx0XHQ8Lz5cblx0XHRcdFx0XHRcdCksXG5cdFx0XHRcdFx0XHRpbWFnZTogPGltZyBjbGFzc05hbWU9XCJlZGl0LXBvc3Qtd2VsY29tZS1ndWlkZV9faW1hZ2VcIiBzcmM9eyBwYWdlLmltYWdlIH0gYWx0PXsgcGFnZS50aXRsZSB9IC8+LFxuXHRcdFx0XHRcdFx0LyogZXNsaW50LWVuYWJsZSByZWFjdC9yZWFjdC1pbi1qc3gtc2NvcGUgKi9cblx0XHRcdFx0XHR9XG5cdFx0XHRcdCk7XG5cdFx0XHR9ICk7XG5cblx0XHRcdHJldHVybiBwYWdlcztcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogU2hvdyBub3RpY2UgaWYgdGhlIHBhZ2UgdGl0bGUgbWF0Y2hlcyBzb21lIGtleXdvcmRzIGZvciBDbGFzc2ljIEVkaXRvci5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqL1xuXHRcdG1heWJlU2hvd0NsYXNzaWNOb3RpY2U6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRpZiAoIGFwcC5pc05vdGljZVZpc2libGUgKSB7XG5cdFx0XHRcdHJldHVybjtcblx0XHRcdH1cblxuXHRcdFx0aWYgKCBhcHAuaXNUaXRsZU1hdGNoS2V5d29yZHMoICQoICcjdGl0bGUnICkudmFsKCkgKSApIHtcblx0XHRcdFx0YXBwLmlzTm90aWNlVmlzaWJsZSA9IHRydWU7XG5cblx0XHRcdFx0JCggJy53cGZvcm1zLWVkaXQtcG9zdC1lZHVjYXRpb24tbm90aWNlJyApLnJlbW92ZUNsYXNzKCAnd3Bmb3Jtcy1oaWRkZW4nICk7XG5cdFx0XHR9XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIFNob3cgbm90aWNlIGlmIHRoZSBwYWdlIHRpdGxlIG1hdGNoZXMgc29tZSBrZXl3b3JkcyBmb3IgR3V0ZW5iZXJnIEVkaXRvci5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqL1xuXHRcdG1heWJlU2hvd0d1dGVuYmVyZ05vdGljZTogZnVuY3Rpb24oKSB7XG5cblx0XHRcdGlmICggYXBwLmlzTm90aWNlVmlzaWJsZSApIHtcblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHRjb25zdCAkcG9zdFRpdGxlID0gYXBwLmlzRnNlKCkgP1xuXHRcdFx0XHQkKCAnaWZyYW1lW25hbWU9XCJlZGl0b3ItY2FudmFzXCJdJyApLmNvbnRlbnRzKCkuZmluZCggJy5lZGl0b3ItcG9zdC10aXRsZV9faW5wdXQnICkgOlxuXHRcdFx0XHQkKCAnLmVkaXRvci1wb3N0LXRpdGxlX19pbnB1dCcgKTtcblx0XHRcdGNvbnN0IHRhZ05hbWUgPSAkcG9zdFRpdGxlLnByb3AoICd0YWdOYW1lJyApO1xuXHRcdFx0Y29uc3QgdGl0bGUgPSB0YWdOYW1lID09PSAnVEVYVEFSRUEnID8gJHBvc3RUaXRsZS52YWwoKSA6ICRwb3N0VGl0bGUudGV4dCgpO1xuXG5cdFx0XHRpZiAoIGFwcC5pc1RpdGxlTWF0Y2hLZXl3b3JkcyggdGl0bGUgKSApIHtcblx0XHRcdFx0YXBwLmlzTm90aWNlVmlzaWJsZSA9IHRydWU7XG5cblx0XHRcdFx0YXBwLnNob3dHdXRlbmJlcmdOb3RpY2UoKTtcblx0XHRcdH1cblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogQWRkIG5vdGljZSBjbGFzcyB3aGVuIHRoZSBkaXN0cmFjdGlvbiBtb2RlIGlzIGVuYWJsZWQuXG5cdFx0ICpcblx0XHQgKiBAc2luY2Uge1ZFUlNJT059XG5cdFx0ICovXG5cdFx0ZGlzdHJhY3Rpb25GcmVlTW9kZVRvZ2dsZTogZnVuY3Rpb24oKSB7XG5cblx0XHRcdGlmICggISBhcHAuaXNOb3RpY2VWaXNpYmxlICkge1xuXHRcdFx0XHRyZXR1cm47XG5cdFx0XHR9XG5cblx0XHRcdGNvbnN0ICRkb2N1bWVudCA9ICQoIGRvY3VtZW50ICk7XG5cdFx0XHRjb25zdCBpc0Rpc3RyYWN0aW9uRnJlZU1vZGUgPSBCb29sZWFuKCAkZG9jdW1lbnQuZmluZCggJy5pcy1kaXN0cmFjdGlvbi1mcmVlJyApLmxlbmd0aCApO1xuXG5cdFx0XHRpZiAoICEgaXNEaXN0cmFjdGlvbkZyZWVNb2RlICkge1xuXHRcdFx0XHRyZXR1cm47XG5cdFx0XHR9XG5cblx0XHRcdGNvbnN0IGlzTm90aWNlSGFzQ2xhc3MgPSBCb29sZWFuKCAkKCAnLndwZm9ybXMtZWRpdC1wb3N0LWVkdWNhdGlvbi1ub3RpY2UnICkubGVuZ3RoICk7XG5cblx0XHRcdGlmICggaXNOb3RpY2VIYXNDbGFzcyApIHtcblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHRjb25zdCAkbm90aWNlQm9keSA9ICRkb2N1bWVudC5maW5kKCAnLndwZm9ybXMtZWRpdC1wb3N0LWVkdWNhdGlvbi1ub3RpY2UtYm9keScgKTtcblx0XHRcdGNvbnN0ICRub3RpY2UgPSAkbm90aWNlQm9keS5jbG9zZXN0KCAnLmNvbXBvbmVudHMtbm90aWNlJyApO1xuXG5cdFx0XHQkbm90aWNlLmFkZENsYXNzKCAnd3Bmb3Jtcy1lZGl0LXBvc3QtZWR1Y2F0aW9uLW5vdGljZScgKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogRGV0ZXJtaW5lIGlmIHRoZSB0aXRsZSBtYXRjaGVzIGtleXdvcmRzLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcGFyYW0ge3N0cmluZ30gdGl0bGVWYWx1ZSBQYWdlIHRpdGxlIHZhbHVlLlxuXHRcdCAqXG5cdFx0ICogQHJldHVybnMge2Jvb2xlYW59IFRydWUgaWYgdGhlIHRpdGxlIG1hdGNoZXMgc29tZSBrZXl3b3Jkcy5cblx0XHQgKi9cblx0XHRpc1RpdGxlTWF0Y2hLZXl3b3JkczogZnVuY3Rpb24oIHRpdGxlVmFsdWUgKSB7XG5cblx0XHRcdGNvbnN0IGV4cGVjdGVkVGl0bGVSZWdleCA9IG5ldyBSZWdFeHAoIC9cXGIoY29udGFjdHxmb3JtKVxcYi9pICk7XG5cblx0XHRcdHJldHVybiBleHBlY3RlZFRpdGxlUmVnZXgudGVzdCggdGl0bGVWYWx1ZSApO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBDbG9zZSBhIG5vdGljZS5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqL1xuXHRcdGNsb3NlTm90aWNlOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0JCggdGhpcyApLmNsb3Nlc3QoICcud3Bmb3Jtcy1lZGl0LXBvc3QtZWR1Y2F0aW9uLW5vdGljZScgKS5yZW1vdmUoKTtcblxuXHRcdFx0YXBwLnVwZGF0ZVVzZXJNZXRhKCk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIFVwZGF0ZSB1c2VyIG1ldGEgYW5kIGRvbid0IHNob3cgdGhlIG5vdGljZSBuZXh0IHRpbWUuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHR1cGRhdGVVc2VyTWV0YSgpIHtcblxuXHRcdFx0JC5wb3N0KFxuXHRcdFx0XHR3cGZvcm1zX2VkaXRfcG9zdF9lZHVjYXRpb24uYWpheF91cmwsXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRhY3Rpb246ICd3cGZvcm1zX2VkdWNhdGlvbl9kaXNtaXNzJyxcblx0XHRcdFx0XHRub25jZTogd3Bmb3Jtc19lZGl0X3Bvc3RfZWR1Y2F0aW9uLmVkdWNhdGlvbl9ub25jZSxcblx0XHRcdFx0XHRzZWN0aW9uOiAnZWRpdC1wb3N0LW5vdGljZScsXG5cdFx0XHRcdH1cblx0XHRcdCk7XG5cdFx0fSxcblx0fTtcblxuXHRyZXR1cm4gYXBwO1xuXG59KCBkb2N1bWVudCwgd2luZG93LCBqUXVlcnkgKSApO1xuXG5XUEZvcm1zRWRpdFBvc3RFZHVjYXRpb24uaW5pdCgpO1xuIl0sIm1hcHBpbmdzIjoiQUFBQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLFlBQVk7O0FBQUM7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBRWIsSUFBTUEsd0JBQXdCLEdBQUdDLE1BQU0sQ0FBQ0Qsd0JBQXdCLElBQU0sVUFBVUUsUUFBUSxFQUFFRCxNQUFNLEVBQUVFLENBQUMsRUFBRztFQUVyRztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtFQUNDLElBQU1DLEdBQUcsR0FBRztJQUVYO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRUMsZUFBZSxFQUFFLEtBQUs7SUFFdEI7QUFDRjtBQUNBO0FBQ0E7QUFDQTtJQUNFQyxJQUFJLEVBQUUsZ0JBQVc7TUFFaEJILENBQUMsQ0FBRUYsTUFBTSxDQUFFLENBQUNNLEVBQUUsQ0FBRSxNQUFNLEVBQUUsWUFBVztRQUVsQztRQUNBLElBQUssT0FBT0osQ0FBQyxDQUFDSyxLQUFLLENBQUNDLElBQUksS0FBSyxVQUFVLEVBQUc7VUFDekNOLENBQUMsQ0FBQ0ssS0FBSyxDQUFDQyxJQUFJLENBQUVMLEdBQUcsQ0FBQ00sSUFBSSxDQUFFO1FBQ3pCLENBQUMsTUFBTTtVQUNOTixHQUFHLENBQUNNLElBQUksRUFBRTtRQUNYO01BQ0QsQ0FBQyxDQUFFO0lBQ0osQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRUEsSUFBSSxFQUFFLGdCQUFXO01BRWhCLElBQUssQ0FBRU4sR0FBRyxDQUFDTyxpQkFBaUIsRUFBRSxFQUFHO1FBQ2hDUCxHQUFHLENBQUNRLHNCQUFzQixFQUFFO1FBQzVCUixHQUFHLENBQUNTLGlCQUFpQixFQUFFO1FBRXZCO01BQ0Q7TUFFQSxJQUFNQyxtQkFBbUIsR0FBR0MsV0FBVyxDQUFFLFlBQVc7UUFFbkQsSUFBSyxDQUFFYixRQUFRLENBQUNjLGFBQWEsQ0FBRSx5REFBeUQsQ0FBRSxFQUFHO1VBQzVGO1FBQ0Q7UUFFQUMsYUFBYSxDQUFFSCxtQkFBbUIsQ0FBRTtRQUVwQyxJQUFLLENBQUVWLEdBQUcsQ0FBQ2MsS0FBSyxFQUFFLEVBQUc7VUFFcEJkLEdBQUcsQ0FBQ2Usd0JBQXdCLEVBQUU7VUFDOUJmLEdBQUcsQ0FBQ2dCLG1CQUFtQixFQUFFO1VBRXpCO1FBQ0Q7UUFFQSxJQUFNQyxNQUFNLEdBQUduQixRQUFRLENBQUNjLGFBQWEsQ0FBRSw4QkFBOEIsQ0FBRTtRQUN2RSxJQUFNTSxRQUFRLEdBQUcsSUFBSUMsZ0JBQWdCLENBQUUsWUFBVztVQUVqRCxJQUFNQyxjQUFjLEdBQUdILE1BQU0sQ0FBQ0ksZUFBZSxJQUFJSixNQUFNLENBQUNLLGFBQWEsQ0FBQ3hCLFFBQVEsSUFBSSxDQUFDLENBQUM7VUFFcEYsSUFBS3NCLGNBQWMsQ0FBQ0csVUFBVSxLQUFLLFVBQVUsSUFBSUgsY0FBYyxDQUFDUixhQUFhLENBQUUsMkJBQTJCLENBQUUsRUFBRztZQUM5R1osR0FBRyxDQUFDZSx3QkFBd0IsRUFBRTtZQUM5QmYsR0FBRyxDQUFDd0IsYUFBYSxFQUFFO1lBRW5CTixRQUFRLENBQUNPLFVBQVUsRUFBRTtVQUN0QjtRQUNELENBQUMsQ0FBRTtRQUNIUCxRQUFRLENBQUNRLE9BQU8sQ0FBRTVCLFFBQVEsQ0FBQzZCLElBQUksRUFBRTtVQUFFQyxPQUFPLEVBQUUsSUFBSTtVQUFFQyxTQUFTLEVBQUU7UUFBSyxDQUFDLENBQUU7TUFDdEUsQ0FBQyxFQUFFLEdBQUcsQ0FBRTtJQUNULENBQUM7SUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0lBQ0VwQixpQkFBaUIsRUFBRSw2QkFBVztNQUU3QixJQUFNcUIsU0FBUyxHQUFHL0IsQ0FBQyxDQUFFRCxRQUFRLENBQUU7TUFFL0IsSUFBSyxDQUFFRSxHQUFHLENBQUNDLGVBQWUsRUFBRztRQUM1QjZCLFNBQVMsQ0FBQzNCLEVBQUUsQ0FBRSxPQUFPLEVBQUUsUUFBUSxFQUFFSCxHQUFHLENBQUNRLHNCQUFzQixDQUFFO01BQzlEO01BRUFzQixTQUFTLENBQUMzQixFQUFFLENBQUUsT0FBTyxFQUFFLDJDQUEyQyxFQUFFSCxHQUFHLENBQUMrQixXQUFXLENBQUU7SUFDdEYsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRWYsbUJBQW1CLEVBQUUsK0JBQVc7TUFFL0IsSUFBTWMsU0FBUyxHQUFHL0IsQ0FBQyxDQUFFRCxRQUFRLENBQUU7TUFFL0JnQyxTQUFTLENBQ1AzQixFQUFFLENBQUUsb0JBQW9CLEVBQUUsbUJBQW1CLEVBQUVILEdBQUcsQ0FBQ2dDLHlCQUF5QixDQUFFO01BRWhGLElBQUtoQyxHQUFHLENBQUNDLGVBQWUsRUFBRztRQUMxQjtNQUNEO01BRUE2QixTQUFTLENBQ1AzQixFQUFFLENBQUUsT0FBTyxFQUFFLDJCQUEyQixFQUFFSCxHQUFHLENBQUNlLHdCQUF3QixDQUFFLENBQ3hFWixFQUFFLENBQUUsb0JBQW9CLEVBQUUsMkJBQTJCLEVBQUVILEdBQUcsQ0FBQ2Usd0JBQXdCLENBQUU7SUFDeEYsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRVMsYUFBYSxFQUFFLHlCQUFXO01BRXpCLElBQU1TLE9BQU8sR0FBR2xDLENBQUMsQ0FBRSw4QkFBOEIsQ0FBRTtNQUVuREEsQ0FBQyxDQUFFRCxRQUFRLENBQUUsQ0FDWEssRUFBRSxDQUFFLG9CQUFvQixFQUFFLG1CQUFtQixFQUFFSCxHQUFHLENBQUNnQyx5QkFBeUIsQ0FBRTtNQUVoRkMsT0FBTyxDQUFDQyxRQUFRLEVBQUUsQ0FDaEIvQixFQUFFLENBQUUsb0JBQW9CLEVBQUUsMkJBQTJCLEVBQUVILEdBQUcsQ0FBQ2Usd0JBQXdCLENBQUU7SUFDeEYsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0lBQ0VSLGlCQUFpQixFQUFFLDZCQUFXO01BRTdCLE9BQU8sT0FBTzRCLEVBQUUsS0FBSyxXQUFXLElBQUksT0FBT0EsRUFBRSxDQUFDQyxNQUFNLEtBQUssV0FBVztJQUNyRSxDQUFDO0lBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7SUFDRXRCLEtBQUssRUFBRSxpQkFBVztNQUVqQixPQUFPdUIsT0FBTyxDQUFFdEMsQ0FBQyxDQUFFLDhCQUE4QixDQUFFLENBQUN1QyxNQUFNLENBQUU7SUFDN0QsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRUMsbUJBQW1CLEVBQUUsK0JBQVc7TUFFL0JKLEVBQUUsQ0FBQ0ssSUFBSSxDQUFDQyxRQUFRLENBQUUsY0FBYyxDQUFFLENBQUNDLGdCQUFnQixDQUNsREMsMkJBQTJCLENBQUNDLGdCQUFnQixDQUFDQyxRQUFRLEVBQ3JEN0MsR0FBRyxDQUFDOEMsMEJBQTBCLEVBQUUsQ0FDaEM7O01BRUQ7TUFDQTtNQUNBLElBQU1DLFNBQVMsR0FBR3BDLFdBQVcsQ0FBRSxZQUFXO1FBRXpDLElBQU1xQyxVQUFVLEdBQUdqRCxDQUFDLENBQUUsMENBQTBDLENBQUU7UUFDbEUsSUFBSyxDQUFFaUQsVUFBVSxDQUFDVixNQUFNLEVBQUc7VUFDMUI7UUFDRDtRQUVBLElBQU1XLE9BQU8sR0FBR0QsVUFBVSxDQUFDRSxPQUFPLENBQUUsb0JBQW9CLENBQUU7UUFDMURELE9BQU8sQ0FBQ0UsUUFBUSxDQUFFLG9DQUFvQyxDQUFFO1FBQ3hERixPQUFPLENBQUNHLElBQUksQ0FBRSx5QkFBeUIsQ0FBRSxDQUFDQyxXQUFXLENBQUUsY0FBYyxDQUFFLENBQUNBLFdBQVcsQ0FBRSxTQUFTLENBQUUsQ0FBQ0YsUUFBUSxDQUFFLFlBQVksQ0FBRTtRQUV6SHRDLGFBQWEsQ0FBRWtDLFNBQVMsQ0FBRTtNQUMzQixDQUFDLEVBQUUsR0FBRyxDQUFFO0lBQ1QsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0lBQ0VELDBCQUEwQixFQUFFLHNDQUFXO01BRXRDLElBQU1RLFVBQVUsR0FBRywyQ0FBMkM7TUFDOUQsSUFBTUMsY0FBYyxHQUFHO1FBQ3RCQyxFQUFFLEVBQUVGLFVBQVU7UUFDZEcsYUFBYSxFQUFFLElBQUk7UUFDbkJDLElBQUksRUFBRSxJQUFJO1FBQ1ZDLGNBQWMsRUFBRSxJQUFJO1FBQ3BCQyxPQUFPLEVBQUUsQ0FDUjtVQUNDQyxTQUFTLEVBQUUsaURBQWlEO1VBQzVEQyxPQUFPLEVBQUUsU0FBUztVQUNsQkMsS0FBSyxFQUFFcEIsMkJBQTJCLENBQUNDLGdCQUFnQixDQUFDb0I7UUFDckQsQ0FBQztNQUVILENBQUM7TUFFRCxJQUFLLENBQUVyQiwyQkFBMkIsQ0FBQ3NCLGVBQWUsRUFBRztRQUVwRFYsY0FBYyxDQUFDSyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUNNLEdBQUcsR0FBR3ZCLDJCQUEyQixDQUFDQyxnQkFBZ0IsQ0FBQ3NCLEdBQUc7UUFFaEYsT0FBT1gsY0FBYztNQUN0QjtNQUVBLElBQU1ZLEtBQUssR0FBR2hDLEVBQUUsQ0FBQ2lDLFVBQVUsQ0FBQ0QsS0FBSztNQUNqQyxJQUFNRSxRQUFRLEdBQUdsQyxFQUFFLENBQUNtQyxPQUFPLENBQUNELFFBQVE7TUFDcEMsSUFBTUUsY0FBYyxHQUFHcEMsRUFBRSxDQUFDcUMsT0FBTyxDQUFDRCxjQUFjO01BQ2hELElBQU1FLGdCQUFnQixHQUFHdEMsRUFBRSxDQUFDcUMsT0FBTyxDQUFDQyxnQkFBZ0I7TUFDcEQsSUFBTUMsaUJBQWlCLEdBQUcsU0FBcEJBLGlCQUFpQixHQUFjO1FBRXBDLGdCQUE4QkwsUUFBUSxDQUFFLElBQUksQ0FBRTtVQUFBO1VBQXRDTSxNQUFNO1VBQUVDLFNBQVM7UUFFekIsSUFBSyxDQUFFRCxNQUFNLEVBQUc7VUFDZixPQUFPLElBQUk7UUFDWjtRQUVBO1VBQUE7VUFDQztVQUNBLG9CQUFDLEtBQUs7WUFDTCxTQUFTLEVBQUMseUJBQXlCO1lBQ25DLFFBQVEsRUFBRyxvQkFBTTtjQUNoQkYsZ0JBQWdCLENBQUVuQixVQUFVLENBQUU7Y0FDOUJzQixTQUFTLENBQUUsS0FBSyxDQUFFO1lBQ25CLENBQUc7WUFDSCxLQUFLLEVBQUc1RSxHQUFHLENBQUM2RSxhQUFhO1VBQUk7UUFDNUI7TUFFSixDQUFDO01BRUR0QixjQUFjLENBQUN1QixTQUFTLEdBQUc5RSxHQUFHLENBQUMrRSxjQUFjO01BQzdDeEIsY0FBYyxDQUFDSyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUNvQixPQUFPLEdBQUc7UUFBQSxPQUFNVCxjQUFjLENBQUVqQixVQUFVLEVBQUU7VUFBRTJCLE1BQU0sRUFBRVA7UUFBa0IsQ0FBQyxDQUFFO01BQUE7TUFFckcsT0FBT25CLGNBQWM7SUFDdEIsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0lBQ0VzQixhQUFhLEVBQUUseUJBQVc7TUFFekIsSUFBTUssS0FBSyxHQUFHLEVBQUU7TUFFaEJ2QywyQkFBMkIsQ0FBQ3NCLGVBQWUsQ0FBQ2tCLE9BQU8sQ0FBRSxVQUFVQyxJQUFJLEVBQUc7UUFDckVGLEtBQUssQ0FBQ0csSUFBSSxDQUNUO1VBQ0M7VUFDQUMsT0FBTyxlQUNOLHVEQUNDO1lBQUksU0FBUyxFQUFDO1VBQWtDLEdBQUdGLElBQUksQ0FBQ0csS0FBSyxDQUFPLGVBQ3BFO1lBQUcsU0FBUyxFQUFDO1VBQStCLEdBQUdILElBQUksQ0FBQ0UsT0FBTyxDQUFNLENBRWxFO1VBQ0RFLEtBQUssZUFBRTtZQUFLLFNBQVMsRUFBQyxnQ0FBZ0M7WUFBQyxHQUFHLEVBQUdKLElBQUksQ0FBQ0ksS0FBTztZQUFDLEdBQUcsRUFBR0osSUFBSSxDQUFDRztVQUFPO1VBQzVGO1FBQ0QsQ0FBQyxDQUNEO01BQ0YsQ0FBQyxDQUFFOztNQUVILE9BQU9MLEtBQUs7SUFDYixDQUFDO0lBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtJQUNFMUUsc0JBQXNCLEVBQUUsa0NBQVc7TUFFbEMsSUFBS1IsR0FBRyxDQUFDQyxlQUFlLEVBQUc7UUFDMUI7TUFDRDtNQUVBLElBQUtELEdBQUcsQ0FBQ3lGLG9CQUFvQixDQUFFMUYsQ0FBQyxDQUFFLFFBQVEsQ0FBRSxDQUFDMkYsR0FBRyxFQUFFLENBQUUsRUFBRztRQUN0RDFGLEdBQUcsQ0FBQ0MsZUFBZSxHQUFHLElBQUk7UUFFMUJGLENBQUMsQ0FBRSxxQ0FBcUMsQ0FBRSxDQUFDc0QsV0FBVyxDQUFFLGdCQUFnQixDQUFFO01BQzNFO0lBQ0QsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRXRDLHdCQUF3QixFQUFFLG9DQUFXO01BRXBDLElBQUtmLEdBQUcsQ0FBQ0MsZUFBZSxFQUFHO1FBQzFCO01BQ0Q7TUFFQSxJQUFNMEYsVUFBVSxHQUFHM0YsR0FBRyxDQUFDYyxLQUFLLEVBQUUsR0FDN0JmLENBQUMsQ0FBRSw4QkFBOEIsQ0FBRSxDQUFDbUMsUUFBUSxFQUFFLENBQUNrQixJQUFJLENBQUUsMkJBQTJCLENBQUUsR0FDbEZyRCxDQUFDLENBQUUsMkJBQTJCLENBQUU7TUFDakMsSUFBTTZGLE9BQU8sR0FBR0QsVUFBVSxDQUFDRSxJQUFJLENBQUUsU0FBUyxDQUFFO01BQzVDLElBQU1OLEtBQUssR0FBR0ssT0FBTyxLQUFLLFVBQVUsR0FBR0QsVUFBVSxDQUFDRCxHQUFHLEVBQUUsR0FBR0MsVUFBVSxDQUFDRyxJQUFJLEVBQUU7TUFFM0UsSUFBSzlGLEdBQUcsQ0FBQ3lGLG9CQUFvQixDQUFFRixLQUFLLENBQUUsRUFBRztRQUN4Q3ZGLEdBQUcsQ0FBQ0MsZUFBZSxHQUFHLElBQUk7UUFFMUJELEdBQUcsQ0FBQ3VDLG1CQUFtQixFQUFFO01BQzFCO0lBQ0QsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRVAseUJBQXlCLEVBQUUscUNBQVc7TUFFckMsSUFBSyxDQUFFaEMsR0FBRyxDQUFDQyxlQUFlLEVBQUc7UUFDNUI7TUFDRDtNQUVBLElBQU02QixTQUFTLEdBQUcvQixDQUFDLENBQUVELFFBQVEsQ0FBRTtNQUMvQixJQUFNaUcscUJBQXFCLEdBQUcxRCxPQUFPLENBQUVQLFNBQVMsQ0FBQ3NCLElBQUksQ0FBRSxzQkFBc0IsQ0FBRSxDQUFDZCxNQUFNLENBQUU7TUFFeEYsSUFBSyxDQUFFeUQscUJBQXFCLEVBQUc7UUFDOUI7TUFDRDtNQUVBLElBQU1DLGdCQUFnQixHQUFHM0QsT0FBTyxDQUFFdEMsQ0FBQyxDQUFFLHFDQUFxQyxDQUFFLENBQUN1QyxNQUFNLENBQUU7TUFFckYsSUFBSzBELGdCQUFnQixFQUFHO1FBQ3ZCO01BQ0Q7TUFFQSxJQUFNQyxXQUFXLEdBQUduRSxTQUFTLENBQUNzQixJQUFJLENBQUUsMENBQTBDLENBQUU7TUFDaEYsSUFBTUgsT0FBTyxHQUFHZ0QsV0FBVyxDQUFDL0MsT0FBTyxDQUFFLG9CQUFvQixDQUFFO01BRTNERCxPQUFPLENBQUNFLFFBQVEsQ0FBRSxvQ0FBb0MsQ0FBRTtJQUN6RCxDQUFDO0lBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0lBQ0VzQyxvQkFBb0IsRUFBRSw4QkFBVVMsVUFBVSxFQUFHO01BRTVDLElBQU1DLGtCQUFrQixHQUFHLElBQUlDLE1BQU0sQ0FBRSxxQkFBcUIsQ0FBRTtNQUU5RCxPQUFPRCxrQkFBa0IsQ0FBQ0UsSUFBSSxDQUFFSCxVQUFVLENBQUU7SUFDN0MsQ0FBQztJQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7SUFDRW5FLFdBQVcsRUFBRSx1QkFBVztNQUV2QmhDLENBQUMsQ0FBRSxJQUFJLENBQUUsQ0FBQ21ELE9BQU8sQ0FBRSxxQ0FBcUMsQ0FBRSxDQUFDb0QsTUFBTSxFQUFFO01BRW5FdEcsR0FBRyxDQUFDK0UsY0FBYyxFQUFFO0lBQ3JCLENBQUM7SUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0lBQ0VBLGNBQWMsNEJBQUc7TUFFaEJoRixDQUFDLENBQUN3RyxJQUFJLENBQ0w1RCwyQkFBMkIsQ0FBQzZELFFBQVEsRUFDcEM7UUFDQ0MsTUFBTSxFQUFFLDJCQUEyQjtRQUNuQ0MsS0FBSyxFQUFFL0QsMkJBQTJCLENBQUNnRSxlQUFlO1FBQ2xEQyxPQUFPLEVBQUU7TUFDVixDQUFDLENBQ0Q7SUFDRjtFQUNELENBQUM7RUFFRCxPQUFPNUcsR0FBRztBQUVYLENBQUMsQ0FBRUYsUUFBUSxFQUFFRCxNQUFNLEVBQUVnSCxNQUFNLENBQUk7QUFFL0JqSCx3QkFBd0IsQ0FBQ00sSUFBSSxFQUFFIn0=
},{}]},{},[1])