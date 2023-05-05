(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/* global wpforms_gutenberg_form_selector, Choices */
/* jshint es3: false, esversion: 6 */

'use strict';

/**
 * Gutenberg editor block.
 *
 * @since 1.8.1
 */
function _slicedToArray(arr, i) { return _arrayWithHoles(arr) || _iterableToArrayLimit(arr, i) || _unsupportedIterableToArray(arr, i) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }
function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i]; return arr2; }
function _iterableToArrayLimit(arr, i) { var _i = null == arr ? null : "undefined" != typeof Symbol && arr[Symbol.iterator] || arr["@@iterator"]; if (null != _i) { var _s, _e, _x, _r, _arr = [], _n = !0, _d = !1; try { if (_x = (_i = _i.call(arr)).next, 0 === i) { if (Object(_i) !== _i) return; _n = !1; } else for (; !(_n = (_s = _x.call(_i)).done) && (_arr.push(_s.value), _arr.length !== i); _n = !0); } catch (err) { _d = !0, _e = err; } finally { try { if (!_n && null != _i.return && (_r = _i.return(), Object(_r) !== _r)) return; } finally { if (_d) throw _e; } } return _arr; } }
function _arrayWithHoles(arr) { if (Array.isArray(arr)) return arr; }
var WPForms = window.WPForms || {};
WPForms.FormSelector = WPForms.FormSelector || function (document, window, $) {
  var _wp = wp,
    _wp$serverSideRender = _wp.serverSideRender,
    ServerSideRender = _wp$serverSideRender === void 0 ? wp.components.ServerSideRender : _wp$serverSideRender;
  var _wp$element = wp.element,
    createElement = _wp$element.createElement,
    Fragment = _wp$element.Fragment,
    useState = _wp$element.useState;
  var registerBlockType = wp.blocks.registerBlockType;
  var _ref = wp.blockEditor || wp.editor,
    InspectorControls = _ref.InspectorControls,
    InspectorAdvancedControls = _ref.InspectorAdvancedControls,
    PanelColorSettings = _ref.PanelColorSettings;
  var _wp$components = wp.components,
    SelectControl = _wp$components.SelectControl,
    ToggleControl = _wp$components.ToggleControl,
    PanelBody = _wp$components.PanelBody,
    Placeholder = _wp$components.Placeholder,
    Flex = _wp$components.Flex,
    FlexBlock = _wp$components.FlexBlock,
    __experimentalUnitControl = _wp$components.__experimentalUnitControl,
    TextareaControl = _wp$components.TextareaControl,
    Button = _wp$components.Button,
    Modal = _wp$components.Modal;
  var _wpforms_gutenberg_fo = wpforms_gutenberg_form_selector,
    strings = _wpforms_gutenberg_fo.strings,
    defaults = _wpforms_gutenberg_fo.defaults,
    sizes = _wpforms_gutenberg_fo.sizes;
  var defaultStyleSettings = defaults;

  /**
   * Blocks runtime data.
   *
   * @since 1.8.1
   *
   * @type {object}
   */
  var blocks = {};

  /**
   * Whether it is needed to trigger server rendering.
   *
   * @since 1.8.1
   *
   * @type {boolean}
   */
  var triggerServerRender = true;

  /**
   * Public functions and properties.
   *
   * @since 1.8.1
   *
   * @type {object}
   */
  var app = {
    /**
     * Start the engine.
     *
     * @since 1.8.1
     */
    init: function init() {
      app.initDefaults();
      app.registerBlock();
      $(app.ready);
    },
    /**
     * Document ready.
     *
     * @since 1.8.1
     */
    ready: function ready() {
      app.events();
    },
    /**
     * Events.
     *
     * @since 1.8.1
     */
    events: function events() {
      $(window).on('wpformsFormSelectorEdit', _.debounce(app.blockEdit, 250)).on('wpformsFormSelectorFormLoaded', _.debounce(app.formLoaded, 250));
    },
    /**
     * Register block.
     *
     * @since 1.8.1
     */
    registerBlock: function registerBlock() {
      registerBlockType('wpforms/form-selector', {
        title: strings.title,
        description: strings.description,
        icon: app.getIcon(),
        keywords: strings.form_keywords,
        category: 'widgets',
        attributes: app.getBlockAttributes(),
        example: {
          attributes: {
            preview: true
          }
        },
        edit: function edit(props) {
          var attributes = props.attributes;
          var formOptions = app.getFormOptions();
          var sizeOptions = app.getSizeOptions();
          var handlers = app.getSettingsFieldsHandlers(props);

          // Store block clientId in attributes.
          props.setAttributes({
            clientId: props.clientId
          });

          // Main block settings.
          var jsx = [app.jsxParts.getMainSettings(attributes, handlers, formOptions)];

          // Form style settings & block content.
          if (attributes.formId) {
            jsx.push(app.jsxParts.getStyleSettings(attributes, handlers, sizeOptions), app.jsxParts.getAdvancedSettings(attributes, handlers), app.jsxParts.getBlockFormContent(props));
            handlers.updateCopyPasteContent();
            $(window).trigger('wpformsFormSelectorEdit', [props]);
            return jsx;
          }

          // Block preview picture.
          if (attributes.preview) {
            jsx.push(app.jsxParts.getBlockPreview());
            return jsx;
          }

          // Block placeholder (form selector).
          jsx.push(app.jsxParts.getBlockPlaceholder(props.attributes, handlers, formOptions));
          return jsx;
        },
        save: function save() {
          return null;
        }
      });
    },
    /**
     * Init default style settings.
     *
     * @since 1.8.1
     */
    initDefaults: function initDefaults() {
      ['formId', 'copyPasteValue'].forEach(function (key) {
        return delete defaultStyleSettings[key];
      });
    },
    /**
     * Block JSX parts.
     *
     * @since 1.8.1
     *
     * @type {object}
     */
    jsxParts: {
      /**
       * Get main settings JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} formOptions Form selector options.
       *
       * @returns {JSX.Element} Main setting JSX code.
       */
      getMainSettings: function getMainSettings(attributes, handlers, formOptions) {
        return /*#__PURE__*/React.createElement(InspectorControls, {
          key: "wpforms-gutenberg-form-selector-inspector-main-settings"
        }, /*#__PURE__*/React.createElement(PanelBody, {
          className: "wpforms-gutenberg-panel",
          title: strings.form_settings
        }, /*#__PURE__*/React.createElement(SelectControl, {
          label: strings.form_selected,
          value: attributes.formId,
          options: formOptions,
          onChange: function onChange(value) {
            return handlers.attrChange('formId', value);
          }
        }), /*#__PURE__*/React.createElement(ToggleControl, {
          label: strings.show_title,
          checked: attributes.displayTitle,
          onChange: function onChange(value) {
            return handlers.attrChange('displayTitle', value);
          }
        }), /*#__PURE__*/React.createElement(ToggleControl, {
          label: strings.show_description,
          checked: attributes.displayDesc,
          onChange: function onChange(value) {
            return handlers.attrChange('displayDesc', value);
          }
        }), /*#__PURE__*/React.createElement("p", {
          className: "wpforms-gutenberg-panel-notice"
        }, /*#__PURE__*/React.createElement("strong", null, strings.panel_notice_head), strings.panel_notice_text, /*#__PURE__*/React.createElement("a", {
          href: strings.panel_notice_link,
          rel: "noreferrer",
          target: "_blank"
        }, strings.panel_notice_link_text))));
      },
      /**
       * Get Field styles JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} sizeOptions Size selector options.
       *
       * @returns {JSX.Element} Field styles JSX code.
       */
      getFieldStyles: function getFieldStyles(attributes, handlers, sizeOptions) {
        // eslint-disable-line max-lines-per-function

        return /*#__PURE__*/React.createElement(PanelBody, {
          className: app.getPanelClass(attributes),
          title: strings.field_styles
        }, /*#__PURE__*/React.createElement("p", {
          className: "wpforms-gutenberg-panel-notice wpforms-use-modern-notice"
        }, /*#__PURE__*/React.createElement("strong", null, strings.use_modern_notice_head), strings.use_modern_notice_text, " ", /*#__PURE__*/React.createElement("a", {
          href: strings.use_modern_notice_link,
          rel: "noreferrer",
          target: "_blank"
        }, strings.learn_more)), /*#__PURE__*/React.createElement("p", {
          className: "wpforms-gutenberg-panel-notice wpforms-warning wpforms-lead-form-notice",
          style: {
            display: 'none'
          }
        }, /*#__PURE__*/React.createElement("strong", null, strings.lead_forms_panel_notice_head), strings.lead_forms_panel_notice_text), /*#__PURE__*/React.createElement(Flex, {
          gap: 4,
          align: "flex-start",
          className: 'wpforms-gutenberg-form-selector-flex',
          justify: "space-between"
        }, /*#__PURE__*/React.createElement(FlexBlock, null, /*#__PURE__*/React.createElement(SelectControl, {
          label: strings.size,
          value: attributes.fieldSize,
          options: sizeOptions,
          onChange: function onChange(value) {
            return handlers.styleAttrChange('fieldSize', value);
          }
        })), /*#__PURE__*/React.createElement(FlexBlock, null, /*#__PURE__*/React.createElement(__experimentalUnitControl, {
          label: strings.border_radius,
          value: attributes.fieldBorderRadius,
          isUnitSelectTabbable: true,
          onChange: function onChange(value) {
            return handlers.styleAttrChange('fieldBorderRadius', value);
          }
        }))), /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-color-picker"
        }, /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-control-label"
        }, strings.colors), /*#__PURE__*/React.createElement(PanelColorSettings, {
          __experimentalIsRenderedInSidebar: true,
          enableAlpha: true,
          showTitle: false,
          className: "wpforms-gutenberg-form-selector-color-panel",
          colorSettings: [{
            value: attributes.fieldBackgroundColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('fieldBackgroundColor', value);
            },
            label: strings.background
          }, {
            value: attributes.fieldBorderColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('fieldBorderColor', value);
            },
            label: strings.border
          }, {
            value: attributes.fieldTextColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('fieldTextColor', value);
            },
            label: strings.text
          }]
        })));
      },
      /**
       * Get Label styles JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} sizeOptions Size selector options.
       *
       * @returns {JSX.Element} Label styles JSX code.
       */
      getLabelStyles: function getLabelStyles(attributes, handlers, sizeOptions) {
        return /*#__PURE__*/React.createElement(PanelBody, {
          className: app.getPanelClass(attributes),
          title: strings.label_styles
        }, /*#__PURE__*/React.createElement(SelectControl, {
          label: strings.size,
          value: attributes.labelSize,
          className: "wpforms-gutenberg-form-selector-fix-bottom-margin",
          options: sizeOptions,
          onChange: function onChange(value) {
            return handlers.styleAttrChange('labelSize', value);
          }
        }), /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-color-picker"
        }, /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-control-label"
        }, strings.colors), /*#__PURE__*/React.createElement(PanelColorSettings, {
          __experimentalIsRenderedInSidebar: true,
          enableAlpha: true,
          showTitle: false,
          className: "wpforms-gutenberg-form-selector-color-panel",
          colorSettings: [{
            value: attributes.labelColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('labelColor', value);
            },
            label: strings.label
          }, {
            value: attributes.labelSublabelColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('labelSublabelColor', value);
            },
            label: strings.sublabel_hints.replace('&amp;', '&')
          }, {
            value: attributes.labelErrorColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('labelErrorColor', value);
            },
            label: strings.error_message
          }]
        })));
      },
      /**
       * Get Button styles JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} sizeOptions Size selector options.
       *
       * @returns {JSX.Element}  Button styles JSX code.
       */
      getButtonStyles: function getButtonStyles(attributes, handlers, sizeOptions) {
        return /*#__PURE__*/React.createElement(PanelBody, {
          className: app.getPanelClass(attributes),
          title: strings.button_styles
        }, /*#__PURE__*/React.createElement(Flex, {
          gap: 4,
          align: "flex-start",
          className: 'wpforms-gutenberg-form-selector-flex',
          justify: "space-between"
        }, /*#__PURE__*/React.createElement(FlexBlock, null, /*#__PURE__*/React.createElement(SelectControl, {
          label: strings.size,
          value: attributes.buttonSize,
          options: sizeOptions,
          onChange: function onChange(value) {
            return handlers.styleAttrChange('buttonSize', value);
          }
        })), /*#__PURE__*/React.createElement(FlexBlock, null, /*#__PURE__*/React.createElement(__experimentalUnitControl, {
          onChange: function onChange(value) {
            return handlers.styleAttrChange('buttonBorderRadius', value);
          },
          label: strings.border_radius,
          isUnitSelectTabbable: true,
          value: attributes.buttonBorderRadius
        }))), /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-color-picker"
        }, /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-control-label"
        }, strings.colors), /*#__PURE__*/React.createElement(PanelColorSettings, {
          __experimentalIsRenderedInSidebar: true,
          enableAlpha: true,
          showTitle: false,
          className: "wpforms-gutenberg-form-selector-color-panel",
          colorSettings: [{
            value: attributes.buttonBackgroundColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('buttonBackgroundColor', value);
            },
            label: strings.background
          }, {
            value: attributes.buttonTextColor,
            onChange: function onChange(value) {
              return handlers.styleAttrChange('buttonTextColor', value);
            },
            label: strings.text
          }]
        }), /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-legend wpforms-button-color-notice"
        }, strings.button_color_notice)));
      },
      /**
       * Get style settings JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} sizeOptions Size selector options.
       *
       * @returns {JSX.Element} Inspector controls JSX code.
       */
      getStyleSettings: function getStyleSettings(attributes, handlers, sizeOptions) {
        return /*#__PURE__*/React.createElement(InspectorControls, {
          key: "wpforms-gutenberg-form-selector-style-settings"
        }, app.jsxParts.getFieldStyles(attributes, handlers, sizeOptions), app.jsxParts.getLabelStyles(attributes, handlers, sizeOptions), app.jsxParts.getButtonStyles(attributes, handlers, sizeOptions));
      },
      /**
       * Get advanced settings JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes Block attributes.
       * @param {object} handlers   Block event handlers.
       *
       * @returns {JSX.Element} Inspector advanced controls JSX code.
       */
      getAdvancedSettings: function getAdvancedSettings(attributes, handlers) {
        var _useState = useState(false),
          _useState2 = _slicedToArray(_useState, 2),
          isOpen = _useState2[0],
          setOpen = _useState2[1];
        var openModal = function openModal() {
          return setOpen(true);
        };
        var closeModal = function closeModal() {
          return setOpen(false);
        };
        return /*#__PURE__*/React.createElement(InspectorAdvancedControls, null, /*#__PURE__*/React.createElement("div", {
          className: app.getPanelClass(attributes)
        }, /*#__PURE__*/React.createElement(TextareaControl, {
          label: strings.copy_paste_settings,
          rows: "4",
          spellCheck: "false",
          value: attributes.copyPasteValue,
          onChange: function onChange(value) {
            return handlers.pasteSettings(value);
          }
        }), /*#__PURE__*/React.createElement("div", {
          className: "wpforms-gutenberg-form-selector-legend",
          dangerouslySetInnerHTML: {
            __html: strings.copy_paste_notice
          }
        }), /*#__PURE__*/React.createElement(Button, {
          className: "wpforms-gutenberg-form-selector-reset-button",
          onClick: openModal
        }, strings.reset_style_settings)), isOpen && /*#__PURE__*/React.createElement(Modal, {
          className: "wpforms-gutenberg-modal",
          title: strings.reset_style_settings,
          onRequestClose: closeModal
        }, /*#__PURE__*/React.createElement("p", null, strings.reset_settings_confirm_text), /*#__PURE__*/React.createElement(Flex, {
          gap: 3,
          align: "center",
          justify: "flex-end"
        }, /*#__PURE__*/React.createElement(Button, {
          isSecondary: true,
          onClick: closeModal
        }, strings.btn_no), /*#__PURE__*/React.createElement(Button, {
          isPrimary: true,
          onClick: function onClick() {
            closeModal();
            handlers.resetSettings();
          }
        }, strings.btn_yes_reset))));
      },
      /**
       * Get block content JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} props Block properties.
       *
       * @returns {JSX.Element} Block content JSX code.
       */
      getBlockFormContent: function getBlockFormContent(props) {
        if (triggerServerRender) {
          return /*#__PURE__*/React.createElement(ServerSideRender, {
            key: "wpforms-gutenberg-form-selector-server-side-renderer",
            block: "wpforms/form-selector",
            attributes: props.attributes
          });
        }
        var clientId = props.clientId;
        var block = app.getBlockContainer(props);

        // In the case of empty content, use server side renderer.
        // This happens when the block is duplicated or converted to a reusable block.
        if (!block || !block.innerHTML) {
          triggerServerRender = true;
          return app.jsxParts.getBlockFormContent(props);
        }
        blocks[clientId] = blocks[clientId] || {};
        blocks[clientId].blockHTML = block.innerHTML;
        blocks[clientId].loadedFormId = props.attributes.formId;
        return /*#__PURE__*/React.createElement(Fragment, {
          key: "wpforms-gutenberg-form-selector-fragment-form-html"
        }, /*#__PURE__*/React.createElement("div", {
          dangerouslySetInnerHTML: {
            __html: blocks[clientId].blockHTML
          }
        }));
      },
      /**
       * Get block preview JSX code.
       *
       * @since 1.8.1
       *
       * @returns {JSX.Element} Block preview JSX code.
       */
      getBlockPreview: function getBlockPreview() {
        return /*#__PURE__*/React.createElement(Fragment, {
          key: "wpforms-gutenberg-form-selector-fragment-block-preview"
        }, /*#__PURE__*/React.createElement("img", {
          src: wpforms_gutenberg_form_selector.block_preview_url,
          style: {
            width: '100%'
          }
        }));
      },
      /**
       * Get block placeholder (form selector) JSX code.
       *
       * @since 1.8.1
       *
       * @param {object} attributes  Block attributes.
       * @param {object} handlers    Block event handlers.
       * @param {object} formOptions Form selector options.
       *
       * @returns {JSX.Element} Block placeholder JSX code.
       */
      getBlockPlaceholder: function getBlockPlaceholder(attributes, handlers, formOptions) {
        return /*#__PURE__*/React.createElement(Placeholder, {
          key: "wpforms-gutenberg-form-selector-wrap",
          className: "wpforms-gutenberg-form-selector-wrap"
        }, /*#__PURE__*/React.createElement("img", {
          src: wpforms_gutenberg_form_selector.logo_url
        }), /*#__PURE__*/React.createElement("h3", null, strings.title), /*#__PURE__*/React.createElement(SelectControl, {
          key: "wpforms-gutenberg-form-selector-select-control",
          value: attributes.formId,
          options: formOptions,
          onChange: function onChange(value) {
            return handlers.attrChange('formId', value);
          }
        }));
      }
    },
    /**
     * Get Style Settings panel class.
     *
     * @since 1.8.1
     *
     * @param {object} attributes Block attributes.
     *
     * @returns {string} Style Settings panel class.
     */
    getPanelClass: function getPanelClass(attributes) {
      var cssClass = 'wpforms-gutenberg-panel wpforms-block-settings-' + attributes.clientId;
      if (!app.isFullStylingEnabled()) {
        cssClass += ' disabled_panel';
      }
      return cssClass;
    },
    /**
     * Determine whether the full styling is enabled.
     *
     * @since 1.8.1
     *
     * @returns {boolean} Whether the full styling is enabled.
     */
    isFullStylingEnabled: function isFullStylingEnabled() {
      return wpforms_gutenberg_form_selector.is_modern_markup && wpforms_gutenberg_form_selector.is_full_styling;
    },
    /**
     * Get block container DOM element.
     *
     * @since 1.8.1
     *
     * @param {object} props Block properties.
     *
     * @returns {Element} Block container.
     */
    getBlockContainer: function getBlockContainer(props) {
      var blockSelector = "#block-".concat(props.clientId, " > div");
      var block = document.querySelector(blockSelector);

      // For FSE / Gutenberg plugin we need to take a look inside the iframe.
      if (!block) {
        var editorCanvas = document.querySelector('iframe[name="editor-canvas"]');
        block = editorCanvas && editorCanvas.contentWindow.document.querySelector(blockSelector);
      }
      return block;
    },
    /**
     * Get settings fields event handlers.
     *
     * @since 1.8.1
     *
     * @param {object} props Block properties.
     *
     * @returns {object} Object that contains event handlers for the settings fields.
     */
    getSettingsFieldsHandlers: function getSettingsFieldsHandlers(props) {
      // eslint-disable-line max-lines-per-function

      return {
        /**
         * Field style attribute change event handler.
         *
         * @since 1.8.1
         *
         * @param {string} attribute Attribute name.
         * @param {string} value     New attribute value.
         */
        styleAttrChange: function styleAttrChange(attribute, value) {
          var block = app.getBlockContainer(props),
            container = block.querySelector("#wpforms-".concat(props.attributes.formId)),
            property = attribute.replace(/[A-Z]/g, function (letter) {
              return "-".concat(letter.toLowerCase());
            }),
            setAttr = {};
          if (container) {
            switch (property) {
              case 'field-size':
              case 'label-size':
              case 'button-size':
                for (var key in sizes[property][value]) {
                  container.style.setProperty("--wpforms-".concat(property, "-").concat(key), sizes[property][value][key]);
                }
                break;
              default:
                container.style.setProperty("--wpforms-".concat(property), value);
            }
          }
          setAttr[attribute] = value;
          props.setAttributes(setAttr);
          triggerServerRender = false;
          this.updateCopyPasteContent();
          $(window).trigger('wpformsFormSelectorStyleAttrChange', [block, props, attribute, value]);
        },
        /**
         * Field regular attribute change event handler.
         *
         * @since 1.8.1
         *
         * @param {string} attribute Attribute name.
         * @param {string} value     New attribute value.
         */
        attrChange: function attrChange(attribute, value) {
          var setAttr = {};
          setAttr[attribute] = value;
          props.setAttributes(setAttr);
          triggerServerRender = true;
          this.updateCopyPasteContent();
        },
        /**
         * Reset Form Styles settings to defaults.
         *
         * @since 1.8.1
         */
        resetSettings: function resetSettings() {
          for (var key in defaultStyleSettings) {
            this.styleAttrChange(key, defaultStyleSettings[key]);
          }
        },
        /**
         * Update content of the "Copy/Paste" fields.
         *
         * @since 1.8.1
         */
        updateCopyPasteContent: function updateCopyPasteContent() {
          var content = {};
          var atts = wp.data.select('core/block-editor').getBlockAttributes(props.clientId);
          for (var key in defaultStyleSettings) {
            content[key] = atts[key];
          }
          props.setAttributes({
            'copyPasteValue': JSON.stringify(content)
          });
        },
        /**
         * Paste settings handler.
         *
         * @since 1.8.1
         *
         * @param {string} value New attribute value.
         */
        pasteSettings: function pasteSettings(value) {
          var pasteAttributes = app.parseValidateJson(value);
          if (!pasteAttributes) {
            wp.data.dispatch('core/notices').createErrorNotice(strings.copy_paste_error, {
              id: 'wpforms-json-parse-error'
            });
            this.updateCopyPasteContent();
            return;
          }
          pasteAttributes.copyPasteValue = value;
          props.setAttributes(pasteAttributes);
          triggerServerRender = true;
        }
      };
    },
    /**
     * Parse and validate JSON string.
     *
     * @since 1.8.1
     *
     * @param {string} value JSON string.
     *
     * @returns {boolean|object} Parsed JSON object OR false on error.
     */
    parseValidateJson: function parseValidateJson(value) {
      if (typeof value !== 'string') {
        return false;
      }
      var atts;
      try {
        atts = JSON.parse(value);
      } catch (error) {
        atts = false;
      }
      return atts;
    },
    /**
     * Get WPForms icon DOM element.
     *
     * @since 1.8.1
     *
     * @returns {DOM.element} WPForms icon DOM element.
     */
    getIcon: function getIcon() {
      return createElement('svg', {
        width: 20,
        height: 20,
        viewBox: '0 0 612 612',
        className: 'dashicon'
      }, createElement('path', {
        fill: 'currentColor',
        d: 'M544,0H68C30.445,0,0,30.445,0,68v476c0,37.556,30.445,68,68,68h476c37.556,0,68-30.444,68-68V68 C612,30.445,581.556,0,544,0z M464.44,68L387.6,120.02L323.34,68H464.44z M288.66,68l-64.26,52.02L147.56,68H288.66z M544,544H68 V68h22.1l136,92.14l79.9-64.6l79.56,64.6l136-92.14H544V544z M114.24,263.16h95.88v-48.28h-95.88V263.16z M114.24,360.4h95.88 v-48.62h-95.88V360.4z M242.76,360.4h255v-48.62h-255V360.4L242.76,360.4z M242.76,263.16h255v-48.28h-255V263.16L242.76,263.16z M368.22,457.3h129.54V408H368.22V457.3z'
      }));
    },
    /**
     * Get block attributes.
     *
     * @since 1.8.1
     *
     * @returns {object} Block attributes.
     */
    getBlockAttributes: function getBlockAttributes() {
      // eslint-disable-line max-lines-per-function

      return {
        clientId: {
          type: 'string',
          default: ''
        },
        formId: {
          type: 'string',
          default: defaults.formId
        },
        displayTitle: {
          type: 'boolean',
          default: defaults.displayTitle
        },
        displayDesc: {
          type: 'boolean',
          default: defaults.displayDesc
        },
        preview: {
          type: 'boolean'
        },
        fieldSize: {
          type: 'string',
          default: defaults.fieldSize
        },
        fieldBorderRadius: {
          type: 'string',
          default: defaults.fieldBorderRadius
        },
        fieldBackgroundColor: {
          type: 'string',
          default: defaults.fieldBackgroundColor
        },
        fieldBorderColor: {
          type: 'string',
          default: defaults.fieldBorderColor
        },
        fieldTextColor: {
          type: 'string',
          default: defaults.fieldTextColor
        },
        labelSize: {
          type: 'string',
          default: defaults.labelSize
        },
        labelColor: {
          type: 'string',
          default: defaults.labelColor
        },
        labelSublabelColor: {
          type: 'string',
          default: defaults.labelSublabelColor
        },
        labelErrorColor: {
          type: 'string',
          default: defaults.labelErrorColor
        },
        buttonSize: {
          type: 'string',
          default: defaults.buttonSize
        },
        buttonBorderRadius: {
          type: 'string',
          default: defaults.buttonBorderRadius
        },
        buttonBackgroundColor: {
          type: 'string',
          default: defaults.buttonBackgroundColor
        },
        buttonTextColor: {
          type: 'string',
          default: defaults.buttonTextColor
        },
        copyPasteValue: {
          type: 'string',
          default: defaults.copyPasteValue
        }
      };
    },
    /**
     * Get form selector options.
     *
     * @since 1.8.1
     *
     * @returns {Array} Form options.
     */
    getFormOptions: function getFormOptions() {
      var formOptions = wpforms_gutenberg_form_selector.forms.map(function (value) {
        return {
          value: value.ID,
          label: value.post_title
        };
      });
      formOptions.unshift({
        value: '',
        label: strings.form_select
      });
      return formOptions;
    },
    /**
     * Get size selector options.
     *
     * @since 1.8.1
     *
     * @returns {Array} Size options.
     */
    getSizeOptions: function getSizeOptions() {
      return [{
        label: strings.small,
        value: 'small'
      }, {
        label: strings.medium,
        value: 'medium'
      }, {
        label: strings.large,
        value: 'large'
      }];
    },
    /**
     * Event `wpformsFormSelectorEdit` handler.
     *
     * @since 1.8.1
     *
     * @param {object} e     Event object.
     * @param {object} props Block properties.
     */
    blockEdit: function blockEdit(e, props) {
      var block = app.getBlockContainer(props);
      if (!block || !block.dataset) {
        return;
      }
      app.initLeadFormSettings(block.parentElement);
    },
    /**
     * Init Lead Form Settings panels.
     *
     * @since 1.8.1
     *
     * @param {Element} block Block element.
     */
    initLeadFormSettings: function initLeadFormSettings(block) {
      if (!block || !block.dataset) {
        return;
      }
      if (!app.isFullStylingEnabled()) {
        return;
      }
      var clientId = block.dataset.block;
      var $form = $(block.querySelector('.wpforms-container'));
      var $panel = $(".wpforms-block-settings-".concat(clientId));
      if ($form.hasClass('wpforms-lead-forms-container')) {
        $panel.addClass('disabled_panel').find('.wpforms-gutenberg-panel-notice.wpforms-lead-form-notice').css('display', 'block');
        $panel.find('.wpforms-gutenberg-panel-notice.wpforms-use-modern-notice').css('display', 'none');
        return;
      }
      $panel.removeClass('disabled_panel').find('.wpforms-gutenberg-panel-notice.wpforms-lead-form-notice').css('display', 'none');
      $panel.find('.wpforms-gutenberg-panel-notice.wpforms-use-modern-notice').css('display', null);
    },
    /**
     * Event `wpformsFormSelectorFormLoaded` handler.
     *
     * @since 1.8.1
     *
     * @param {object} e Event object.
     */
    formLoaded: function formLoaded(e) {
      app.initLeadFormSettings(e.detail.block);
      app.updateAccentColors(e.detail);
      app.loadChoicesJS(e.detail);
      app.initRichTextField(e.detail.formId);
      $(e.detail.block).off('click').on('click', app.blockClick);
    },
    /**
     * Click on the block event handler.
     *
     * @since 1.8.1
     *
     * @param {object} e Event object.
     */
    blockClick: function blockClick(e) {
      app.initLeadFormSettings(e.currentTarget);
    },
    /**
     * Update accent colors of some fields in GB block in Modern Markup mode.
     *
     * @since 1.8.1
     *
     * @param {object} detail Event details object.
     */
    updateAccentColors: function updateAccentColors(detail) {
      if (!wpforms_gutenberg_form_selector.is_modern_markup || !window.WPForms || !window.WPForms.FrontendModern || !detail.block) {
        return;
      }
      var $form = $(detail.block.querySelector("#wpforms-".concat(detail.formId))),
        FrontendModern = window.WPForms.FrontendModern;
      FrontendModern.updateGBBlockPageIndicatorColor($form);
      FrontendModern.updateGBBlockIconChoicesColor($form);
      FrontendModern.updateGBBlockRatingColor($form);
    },
    /**
     * Init Modern style Dropdown fields (<select>).
     *
     * @since 1.8.1
     *
     * @param {object} detail Event details object.
     */
    loadChoicesJS: function loadChoicesJS(detail) {
      if (typeof window.Choices !== 'function') {
        return;
      }
      var $form = $(detail.block.querySelector("#wpforms-".concat(detail.formId)));
      $form.find('.choicesjs-select').each(function (idx, el) {
        var $el = $(el);
        if ($el.data('choice') === 'active') {
          return;
        }
        var args = window.wpforms_choicesjs_config || {},
          searchEnabled = $el.data('search-enabled'),
          $field = $el.closest('.wpforms-field');
        args.searchEnabled = 'undefined' !== typeof searchEnabled ? searchEnabled : true;
        args.callbackOnInit = function () {
          var self = this,
            $element = $(self.passedElement.element),
            $input = $(self.input.element),
            sizeClass = $element.data('size-class');

          // Add CSS-class for size.
          if (sizeClass) {
            $(self.containerOuter.element).addClass(sizeClass);
          }

          /**
           * If a multiple select has selected choices - hide a placeholder text.
           * In case if select is empty - we return placeholder text back.
           */
          if ($element.prop('multiple')) {
            // On init event.
            $input.data('placeholder', $input.attr('placeholder'));
            if (self.getValue(true).length) {
              $input.removeAttr('placeholder');
            }
          }
          this.disable();
          $field.find('.is-disabled').removeClass('is-disabled');
        };
        try {
          var choicesInstance = new Choices(el, args);

          // Save Choices.js instance for future access.
          $el.data('choicesjs', choicesInstance);
        } catch (e) {} // eslint-disable-line no-empty
      });
    },

    /**
     * Initialize RichText field.
     *
     * @since 1.8.1
     *
     * @param {int} formId Form ID.
     */
    initRichTextField: function initRichTextField(formId) {
      // Set default tab to `Visual`.
      $("#wpforms-".concat(formId, " .wp-editor-wrap")).removeClass('html-active').addClass('tmce-active');
    }
  };

  // Provide access to public functions/properties.
  return app;
}(document, window, jQuery);

// Initialize.
WPForms.FormSelector.init();
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJXUEZvcm1zIiwid2luZG93IiwiRm9ybVNlbGVjdG9yIiwiZG9jdW1lbnQiLCIkIiwid3AiLCJzZXJ2ZXJTaWRlUmVuZGVyIiwiU2VydmVyU2lkZVJlbmRlciIsImNvbXBvbmVudHMiLCJlbGVtZW50IiwiY3JlYXRlRWxlbWVudCIsIkZyYWdtZW50IiwidXNlU3RhdGUiLCJyZWdpc3RlckJsb2NrVHlwZSIsImJsb2NrcyIsImJsb2NrRWRpdG9yIiwiZWRpdG9yIiwiSW5zcGVjdG9yQ29udHJvbHMiLCJJbnNwZWN0b3JBZHZhbmNlZENvbnRyb2xzIiwiUGFuZWxDb2xvclNldHRpbmdzIiwiU2VsZWN0Q29udHJvbCIsIlRvZ2dsZUNvbnRyb2wiLCJQYW5lbEJvZHkiLCJQbGFjZWhvbGRlciIsIkZsZXgiLCJGbGV4QmxvY2siLCJfX2V4cGVyaW1lbnRhbFVuaXRDb250cm9sIiwiVGV4dGFyZWFDb250cm9sIiwiQnV0dG9uIiwiTW9kYWwiLCJ3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yIiwic3RyaW5ncyIsImRlZmF1bHRzIiwic2l6ZXMiLCJkZWZhdWx0U3R5bGVTZXR0aW5ncyIsInRyaWdnZXJTZXJ2ZXJSZW5kZXIiLCJhcHAiLCJpbml0IiwiaW5pdERlZmF1bHRzIiwicmVnaXN0ZXJCbG9jayIsInJlYWR5IiwiZXZlbnRzIiwib24iLCJfIiwiZGVib3VuY2UiLCJibG9ja0VkaXQiLCJmb3JtTG9hZGVkIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImljb24iLCJnZXRJY29uIiwia2V5d29yZHMiLCJmb3JtX2tleXdvcmRzIiwiY2F0ZWdvcnkiLCJhdHRyaWJ1dGVzIiwiZ2V0QmxvY2tBdHRyaWJ1dGVzIiwiZXhhbXBsZSIsInByZXZpZXciLCJlZGl0IiwicHJvcHMiLCJmb3JtT3B0aW9ucyIsImdldEZvcm1PcHRpb25zIiwic2l6ZU9wdGlvbnMiLCJnZXRTaXplT3B0aW9ucyIsImhhbmRsZXJzIiwiZ2V0U2V0dGluZ3NGaWVsZHNIYW5kbGVycyIsInNldEF0dHJpYnV0ZXMiLCJjbGllbnRJZCIsImpzeCIsImpzeFBhcnRzIiwiZ2V0TWFpblNldHRpbmdzIiwiZm9ybUlkIiwicHVzaCIsImdldFN0eWxlU2V0dGluZ3MiLCJnZXRBZHZhbmNlZFNldHRpbmdzIiwiZ2V0QmxvY2tGb3JtQ29udGVudCIsInVwZGF0ZUNvcHlQYXN0ZUNvbnRlbnQiLCJ0cmlnZ2VyIiwiZ2V0QmxvY2tQcmV2aWV3IiwiZ2V0QmxvY2tQbGFjZWhvbGRlciIsInNhdmUiLCJmb3JFYWNoIiwia2V5IiwiZm9ybV9zZXR0aW5ncyIsImZvcm1fc2VsZWN0ZWQiLCJ2YWx1ZSIsImF0dHJDaGFuZ2UiLCJzaG93X3RpdGxlIiwiZGlzcGxheVRpdGxlIiwic2hvd19kZXNjcmlwdGlvbiIsImRpc3BsYXlEZXNjIiwicGFuZWxfbm90aWNlX2hlYWQiLCJwYW5lbF9ub3RpY2VfdGV4dCIsInBhbmVsX25vdGljZV9saW5rIiwicGFuZWxfbm90aWNlX2xpbmtfdGV4dCIsImdldEZpZWxkU3R5bGVzIiwiZ2V0UGFuZWxDbGFzcyIsImZpZWxkX3N0eWxlcyIsInVzZV9tb2Rlcm5fbm90aWNlX2hlYWQiLCJ1c2VfbW9kZXJuX25vdGljZV90ZXh0IiwidXNlX21vZGVybl9ub3RpY2VfbGluayIsImxlYXJuX21vcmUiLCJkaXNwbGF5IiwibGVhZF9mb3Jtc19wYW5lbF9ub3RpY2VfaGVhZCIsImxlYWRfZm9ybXNfcGFuZWxfbm90aWNlX3RleHQiLCJzaXplIiwiZmllbGRTaXplIiwic3R5bGVBdHRyQ2hhbmdlIiwiYm9yZGVyX3JhZGl1cyIsImZpZWxkQm9yZGVyUmFkaXVzIiwiY29sb3JzIiwiZmllbGRCYWNrZ3JvdW5kQ29sb3IiLCJvbkNoYW5nZSIsImxhYmVsIiwiYmFja2dyb3VuZCIsImZpZWxkQm9yZGVyQ29sb3IiLCJib3JkZXIiLCJmaWVsZFRleHRDb2xvciIsInRleHQiLCJnZXRMYWJlbFN0eWxlcyIsImxhYmVsX3N0eWxlcyIsImxhYmVsU2l6ZSIsImxhYmVsQ29sb3IiLCJsYWJlbFN1YmxhYmVsQ29sb3IiLCJzdWJsYWJlbF9oaW50cyIsInJlcGxhY2UiLCJsYWJlbEVycm9yQ29sb3IiLCJlcnJvcl9tZXNzYWdlIiwiZ2V0QnV0dG9uU3R5bGVzIiwiYnV0dG9uX3N0eWxlcyIsImJ1dHRvblNpemUiLCJidXR0b25Cb3JkZXJSYWRpdXMiLCJidXR0b25CYWNrZ3JvdW5kQ29sb3IiLCJidXR0b25UZXh0Q29sb3IiLCJidXR0b25fY29sb3Jfbm90aWNlIiwiaXNPcGVuIiwic2V0T3BlbiIsIm9wZW5Nb2RhbCIsImNsb3NlTW9kYWwiLCJjb3B5X3Bhc3RlX3NldHRpbmdzIiwiY29weVBhc3RlVmFsdWUiLCJwYXN0ZVNldHRpbmdzIiwiX19odG1sIiwiY29weV9wYXN0ZV9ub3RpY2UiLCJyZXNldF9zdHlsZV9zZXR0aW5ncyIsInJlc2V0X3NldHRpbmdzX2NvbmZpcm1fdGV4dCIsImJ0bl9ubyIsInJlc2V0U2V0dGluZ3MiLCJidG5feWVzX3Jlc2V0IiwiYmxvY2siLCJnZXRCbG9ja0NvbnRhaW5lciIsImlubmVySFRNTCIsImJsb2NrSFRNTCIsImxvYWRlZEZvcm1JZCIsImJsb2NrX3ByZXZpZXdfdXJsIiwid2lkdGgiLCJsb2dvX3VybCIsImNzc0NsYXNzIiwiaXNGdWxsU3R5bGluZ0VuYWJsZWQiLCJpc19tb2Rlcm5fbWFya3VwIiwiaXNfZnVsbF9zdHlsaW5nIiwiYmxvY2tTZWxlY3RvciIsInF1ZXJ5U2VsZWN0b3IiLCJlZGl0b3JDYW52YXMiLCJjb250ZW50V2luZG93IiwiYXR0cmlidXRlIiwiY29udGFpbmVyIiwicHJvcGVydHkiLCJsZXR0ZXIiLCJ0b0xvd2VyQ2FzZSIsInNldEF0dHIiLCJzdHlsZSIsInNldFByb3BlcnR5IiwiY29udGVudCIsImF0dHMiLCJkYXRhIiwic2VsZWN0IiwiSlNPTiIsInN0cmluZ2lmeSIsInBhc3RlQXR0cmlidXRlcyIsInBhcnNlVmFsaWRhdGVKc29uIiwiZGlzcGF0Y2giLCJjcmVhdGVFcnJvck5vdGljZSIsImNvcHlfcGFzdGVfZXJyb3IiLCJpZCIsInBhcnNlIiwiZXJyb3IiLCJoZWlnaHQiLCJ2aWV3Qm94IiwiY2xhc3NOYW1lIiwiZmlsbCIsImQiLCJ0eXBlIiwiZGVmYXVsdCIsImZvcm1zIiwibWFwIiwiSUQiLCJwb3N0X3RpdGxlIiwidW5zaGlmdCIsImZvcm1fc2VsZWN0Iiwic21hbGwiLCJtZWRpdW0iLCJsYXJnZSIsImUiLCJkYXRhc2V0IiwiaW5pdExlYWRGb3JtU2V0dGluZ3MiLCJwYXJlbnRFbGVtZW50IiwiJGZvcm0iLCIkcGFuZWwiLCJoYXNDbGFzcyIsImFkZENsYXNzIiwiZmluZCIsImNzcyIsInJlbW92ZUNsYXNzIiwiZGV0YWlsIiwidXBkYXRlQWNjZW50Q29sb3JzIiwibG9hZENob2ljZXNKUyIsImluaXRSaWNoVGV4dEZpZWxkIiwib2ZmIiwiYmxvY2tDbGljayIsImN1cnJlbnRUYXJnZXQiLCJGcm9udGVuZE1vZGVybiIsInVwZGF0ZUdCQmxvY2tQYWdlSW5kaWNhdG9yQ29sb3IiLCJ1cGRhdGVHQkJsb2NrSWNvbkNob2ljZXNDb2xvciIsInVwZGF0ZUdCQmxvY2tSYXRpbmdDb2xvciIsIkNob2ljZXMiLCJlYWNoIiwiaWR4IiwiZWwiLCIkZWwiLCJhcmdzIiwid3Bmb3Jtc19jaG9pY2VzanNfY29uZmlnIiwic2VhcmNoRW5hYmxlZCIsIiRmaWVsZCIsImNsb3Nlc3QiLCJjYWxsYmFja09uSW5pdCIsInNlbGYiLCIkZWxlbWVudCIsInBhc3NlZEVsZW1lbnQiLCIkaW5wdXQiLCJpbnB1dCIsInNpemVDbGFzcyIsImNvbnRhaW5lck91dGVyIiwicHJvcCIsImF0dHIiLCJnZXRWYWx1ZSIsImxlbmd0aCIsInJlbW92ZUF0dHIiLCJkaXNhYmxlIiwiY2hvaWNlc0luc3RhbmNlIiwialF1ZXJ5Il0sInNvdXJjZXMiOlsiZmFrZV8xNTU3YTc1LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qIGdsb2JhbCB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLCBDaG9pY2VzICovXG4vKiBqc2hpbnQgZXMzOiBmYWxzZSwgZXN2ZXJzaW9uOiA2ICovXG5cbid1c2Ugc3RyaWN0JztcblxuLyoqXG4gKiBHdXRlbmJlcmcgZWRpdG9yIGJsb2NrLlxuICpcbiAqIEBzaW5jZSAxLjguMVxuICovXG52YXIgV1BGb3JtcyA9IHdpbmRvdy5XUEZvcm1zIHx8IHt9O1xuXG5XUEZvcm1zLkZvcm1TZWxlY3RvciA9IFdQRm9ybXMuRm9ybVNlbGVjdG9yIHx8ICggZnVuY3Rpb24oIGRvY3VtZW50LCB3aW5kb3csICQgKSB7XG5cblx0Y29uc3QgeyBzZXJ2ZXJTaWRlUmVuZGVyOiBTZXJ2ZXJTaWRlUmVuZGVyID0gd3AuY29tcG9uZW50cy5TZXJ2ZXJTaWRlUmVuZGVyIH0gPSB3cDtcblx0Y29uc3QgeyBjcmVhdGVFbGVtZW50LCBGcmFnbWVudCwgdXNlU3RhdGUgfSA9IHdwLmVsZW1lbnQ7XG5cdGNvbnN0IHsgcmVnaXN0ZXJCbG9ja1R5cGUgfSA9IHdwLmJsb2Nrcztcblx0Y29uc3QgeyBJbnNwZWN0b3JDb250cm9scywgSW5zcGVjdG9yQWR2YW5jZWRDb250cm9scywgUGFuZWxDb2xvclNldHRpbmdzIH0gPSB3cC5ibG9ja0VkaXRvciB8fCB3cC5lZGl0b3I7XG5cdGNvbnN0IHsgU2VsZWN0Q29udHJvbCwgVG9nZ2xlQ29udHJvbCwgUGFuZWxCb2R5LCBQbGFjZWhvbGRlciwgRmxleCwgRmxleEJsb2NrLCBfX2V4cGVyaW1lbnRhbFVuaXRDb250cm9sLCBUZXh0YXJlYUNvbnRyb2wsIEJ1dHRvbiwgTW9kYWwgfSA9IHdwLmNvbXBvbmVudHM7XG5cdGNvbnN0IHsgc3RyaW5ncywgZGVmYXVsdHMsIHNpemVzIH0gPSB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yO1xuXHRjb25zdCBkZWZhdWx0U3R5bGVTZXR0aW5ncyA9IGRlZmF1bHRzO1xuXG5cdC8qKlxuXHQgKiBCbG9ja3MgcnVudGltZSBkYXRhLlxuXHQgKlxuXHQgKiBAc2luY2UgMS44LjFcblx0ICpcblx0ICogQHR5cGUge29iamVjdH1cblx0ICovXG5cdGxldCBibG9ja3MgPSB7fTtcblxuXHQvKipcblx0ICogV2hldGhlciBpdCBpcyBuZWVkZWQgdG8gdHJpZ2dlciBzZXJ2ZXIgcmVuZGVyaW5nLlxuXHQgKlxuXHQgKiBAc2luY2UgMS44LjFcblx0ICpcblx0ICogQHR5cGUge2Jvb2xlYW59XG5cdCAqL1xuXHRsZXQgdHJpZ2dlclNlcnZlclJlbmRlciA9IHRydWU7XG5cblx0LyoqXG5cdCAqIFB1YmxpYyBmdW5jdGlvbnMgYW5kIHByb3BlcnRpZXMuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjguMVxuXHQgKlxuXHQgKiBAdHlwZSB7b2JqZWN0fVxuXHQgKi9cblx0Y29uc3QgYXBwID0ge1xuXG5cdFx0LyoqXG5cdFx0ICogU3RhcnQgdGhlIGVuZ2luZS5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqL1xuXHRcdGluaXQ6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRhcHAuaW5pdERlZmF1bHRzKCk7XG5cdFx0XHRhcHAucmVnaXN0ZXJCbG9jaygpO1xuXG5cdFx0XHQkKCBhcHAucmVhZHkgKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogRG9jdW1lbnQgcmVhZHkuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKi9cblx0XHRyZWFkeTogZnVuY3Rpb24oKSB7XG5cblx0XHRcdGFwcC5ldmVudHMoKTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogRXZlbnRzLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICovXG5cdFx0ZXZlbnRzOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0JCggd2luZG93IClcblx0XHRcdFx0Lm9uKCAnd3Bmb3Jtc0Zvcm1TZWxlY3RvckVkaXQnLCBfLmRlYm91bmNlKCBhcHAuYmxvY2tFZGl0LCAyNTAgKSApXG5cdFx0XHRcdC5vbiggJ3dwZm9ybXNGb3JtU2VsZWN0b3JGb3JtTG9hZGVkJywgXy5kZWJvdW5jZSggYXBwLmZvcm1Mb2FkZWQsIDI1MCApICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIFJlZ2lzdGVyIGJsb2NrLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICovXG5cdFx0cmVnaXN0ZXJCbG9jazogZnVuY3Rpb24oKSB7XG5cblx0XHRcdHJlZ2lzdGVyQmxvY2tUeXBlKCAnd3Bmb3Jtcy9mb3JtLXNlbGVjdG9yJywge1xuXHRcdFx0XHR0aXRsZTogc3RyaW5ncy50aXRsZSxcblx0XHRcdFx0ZGVzY3JpcHRpb246IHN0cmluZ3MuZGVzY3JpcHRpb24sXG5cdFx0XHRcdGljb246IGFwcC5nZXRJY29uKCksXG5cdFx0XHRcdGtleXdvcmRzOiBzdHJpbmdzLmZvcm1fa2V5d29yZHMsXG5cdFx0XHRcdGNhdGVnb3J5OiAnd2lkZ2V0cycsXG5cdFx0XHRcdGF0dHJpYnV0ZXM6IGFwcC5nZXRCbG9ja0F0dHJpYnV0ZXMoKSxcblx0XHRcdFx0ZXhhbXBsZToge1xuXHRcdFx0XHRcdGF0dHJpYnV0ZXM6IHtcblx0XHRcdFx0XHRcdHByZXZpZXc6IHRydWUsXG5cdFx0XHRcdFx0fSxcblx0XHRcdFx0fSxcblx0XHRcdFx0ZWRpdDogZnVuY3Rpb24oIHByb3BzICkge1xuXG5cdFx0XHRcdFx0Y29uc3QgeyBhdHRyaWJ1dGVzIH0gPSBwcm9wcztcblx0XHRcdFx0XHRjb25zdCBmb3JtT3B0aW9ucyA9IGFwcC5nZXRGb3JtT3B0aW9ucygpO1xuXHRcdFx0XHRcdGNvbnN0IHNpemVPcHRpb25zID0gYXBwLmdldFNpemVPcHRpb25zKCk7XG5cdFx0XHRcdFx0Y29uc3QgaGFuZGxlcnMgPSBhcHAuZ2V0U2V0dGluZ3NGaWVsZHNIYW5kbGVycyggcHJvcHMgKTtcblxuXHRcdFx0XHRcdC8vIFN0b3JlIGJsb2NrIGNsaWVudElkIGluIGF0dHJpYnV0ZXMuXG5cdFx0XHRcdFx0cHJvcHMuc2V0QXR0cmlidXRlcygge1xuXHRcdFx0XHRcdFx0Y2xpZW50SWQ6IHByb3BzLmNsaWVudElkLFxuXHRcdFx0XHRcdH0gKTtcblxuXHRcdFx0XHRcdC8vIE1haW4gYmxvY2sgc2V0dGluZ3MuXG5cdFx0XHRcdFx0bGV0IGpzeCA9IFtcblx0XHRcdFx0XHRcdGFwcC5qc3hQYXJ0cy5nZXRNYWluU2V0dGluZ3MoIGF0dHJpYnV0ZXMsIGhhbmRsZXJzLCBmb3JtT3B0aW9ucyApLFxuXHRcdFx0XHRcdF07XG5cblx0XHRcdFx0XHQvLyBGb3JtIHN0eWxlIHNldHRpbmdzICYgYmxvY2sgY29udGVudC5cblx0XHRcdFx0XHRpZiAoIGF0dHJpYnV0ZXMuZm9ybUlkICkge1xuXHRcdFx0XHRcdFx0anN4LnB1c2goXG5cdFx0XHRcdFx0XHRcdGFwcC5qc3hQYXJ0cy5nZXRTdHlsZVNldHRpbmdzKCBhdHRyaWJ1dGVzLCBoYW5kbGVycywgc2l6ZU9wdGlvbnMgKSxcblx0XHRcdFx0XHRcdFx0YXBwLmpzeFBhcnRzLmdldEFkdmFuY2VkU2V0dGluZ3MoIGF0dHJpYnV0ZXMsIGhhbmRsZXJzICksXG5cdFx0XHRcdFx0XHRcdGFwcC5qc3hQYXJ0cy5nZXRCbG9ja0Zvcm1Db250ZW50KCBwcm9wcyApLFxuXHRcdFx0XHRcdFx0KTtcblxuXHRcdFx0XHRcdFx0aGFuZGxlcnMudXBkYXRlQ29weVBhc3RlQ29udGVudCgpO1xuXG5cdFx0XHRcdFx0XHQkKCB3aW5kb3cgKS50cmlnZ2VyKCAnd3Bmb3Jtc0Zvcm1TZWxlY3RvckVkaXQnLCBbIHByb3BzIF0gKTtcblxuXHRcdFx0XHRcdFx0cmV0dXJuIGpzeDtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHQvLyBCbG9jayBwcmV2aWV3IHBpY3R1cmUuXG5cdFx0XHRcdFx0aWYgKCBhdHRyaWJ1dGVzLnByZXZpZXcgKSB7XG5cdFx0XHRcdFx0XHRqc3gucHVzaChcblx0XHRcdFx0XHRcdFx0YXBwLmpzeFBhcnRzLmdldEJsb2NrUHJldmlldygpLFxuXHRcdFx0XHRcdFx0KTtcblxuXHRcdFx0XHRcdFx0cmV0dXJuIGpzeDtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHQvLyBCbG9jayBwbGFjZWhvbGRlciAoZm9ybSBzZWxlY3RvcikuXG5cdFx0XHRcdFx0anN4LnB1c2goXG5cdFx0XHRcdFx0XHRhcHAuanN4UGFydHMuZ2V0QmxvY2tQbGFjZWhvbGRlciggcHJvcHMuYXR0cmlidXRlcywgaGFuZGxlcnMsIGZvcm1PcHRpb25zICksXG5cdFx0XHRcdFx0KTtcblxuXHRcdFx0XHRcdHJldHVybiBqc3g7XG5cdFx0XHRcdH0sXG5cdFx0XHRcdHNhdmU6ICgpID0+IG51bGwsXG5cdFx0XHR9ICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEluaXQgZGVmYXVsdCBzdHlsZSBzZXR0aW5ncy5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqL1xuXHRcdGluaXREZWZhdWx0czogZnVuY3Rpb24oKSB7XG5cblx0XHRcdFsgJ2Zvcm1JZCcsICdjb3B5UGFzdGVWYWx1ZScgXS5mb3JFYWNoKCBrZXkgPT4gZGVsZXRlIGRlZmF1bHRTdHlsZVNldHRpbmdzWyBrZXkgXSApO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBCbG9jayBKU1ggcGFydHMuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKlxuXHRcdCAqIEB0eXBlIHtvYmplY3R9XG5cdFx0ICovXG5cdFx0anN4UGFydHM6IHtcblxuXHRcdFx0LyoqXG5cdFx0XHQgKiBHZXQgbWFpbiBzZXR0aW5ncyBKU1ggY29kZS5cblx0XHRcdCAqXG5cdFx0XHQgKiBAc2luY2UgMS44LjFcblx0XHRcdCAqXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlcyAgQmxvY2sgYXR0cmlidXRlcy5cblx0XHRcdCAqIEBwYXJhbSB7b2JqZWN0fSBoYW5kbGVycyAgICBCbG9jayBldmVudCBoYW5kbGVycy5cblx0XHRcdCAqIEBwYXJhbSB7b2JqZWN0fSBmb3JtT3B0aW9ucyBGb3JtIHNlbGVjdG9yIG9wdGlvbnMuXG5cdFx0XHQgKlxuXHRcdFx0ICogQHJldHVybnMge0pTWC5FbGVtZW50fSBNYWluIHNldHRpbmcgSlNYIGNvZGUuXG5cdFx0XHQgKi9cblx0XHRcdGdldE1haW5TZXR0aW5nczogZnVuY3Rpb24oIGF0dHJpYnV0ZXMsIGhhbmRsZXJzLCBmb3JtT3B0aW9ucyApIHtcblxuXHRcdFx0XHRyZXR1cm4gKFxuXHRcdFx0XHRcdDxJbnNwZWN0b3JDb250cm9scyBrZXk9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLWluc3BlY3Rvci1tYWluLXNldHRpbmdzXCI+XG5cdFx0XHRcdFx0XHQ8UGFuZWxCb2R5IGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLXBhbmVsXCIgdGl0bGU9eyBzdHJpbmdzLmZvcm1fc2V0dGluZ3MgfT5cblx0XHRcdFx0XHRcdFx0PFNlbGVjdENvbnRyb2xcblx0XHRcdFx0XHRcdFx0XHRsYWJlbD17IHN0cmluZ3MuZm9ybV9zZWxlY3RlZCB9XG5cdFx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmZvcm1JZCB9XG5cdFx0XHRcdFx0XHRcdFx0b3B0aW9ucz17IGZvcm1PcHRpb25zIH1cblx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZT17IHZhbHVlID0+IGhhbmRsZXJzLmF0dHJDaGFuZ2UoICdmb3JtSWQnLCB2YWx1ZSApIH1cblx0XHRcdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHRcdFx0PFRvZ2dsZUNvbnRyb2xcblx0XHRcdFx0XHRcdFx0XHRsYWJlbD17IHN0cmluZ3Muc2hvd190aXRsZSB9XG5cdFx0XHRcdFx0XHRcdFx0Y2hlY2tlZD17IGF0dHJpYnV0ZXMuZGlzcGxheVRpdGxlIH1cblx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZT17IHZhbHVlID0+IGhhbmRsZXJzLmF0dHJDaGFuZ2UoICdkaXNwbGF5VGl0bGUnLCB2YWx1ZSApIH1cblx0XHRcdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHRcdFx0PFRvZ2dsZUNvbnRyb2xcblx0XHRcdFx0XHRcdFx0XHRsYWJlbD17IHN0cmluZ3Muc2hvd19kZXNjcmlwdGlvbiB9XG5cdFx0XHRcdFx0XHRcdFx0Y2hlY2tlZD17IGF0dHJpYnV0ZXMuZGlzcGxheURlc2MgfVxuXHRcdFx0XHRcdFx0XHRcdG9uQ2hhbmdlPXsgdmFsdWUgPT4gaGFuZGxlcnMuYXR0ckNoYW5nZSggJ2Rpc3BsYXlEZXNjJywgdmFsdWUgKSB9XG5cdFx0XHRcdFx0XHRcdC8+XG5cdFx0XHRcdFx0XHRcdDxwIGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLXBhbmVsLW5vdGljZVwiPlxuXHRcdFx0XHRcdFx0XHRcdDxzdHJvbmc+eyBzdHJpbmdzLnBhbmVsX25vdGljZV9oZWFkIH08L3N0cm9uZz5cblx0XHRcdFx0XHRcdFx0XHR7IHN0cmluZ3MucGFuZWxfbm90aWNlX3RleHQgfVxuXHRcdFx0XHRcdFx0XHRcdDxhIGhyZWY9e3N0cmluZ3MucGFuZWxfbm90aWNlX2xpbmt9IHJlbD1cIm5vcmVmZXJyZXJcIiB0YXJnZXQ9XCJfYmxhbmtcIj57IHN0cmluZ3MucGFuZWxfbm90aWNlX2xpbmtfdGV4dCB9PC9hPlxuXHRcdFx0XHRcdFx0XHQ8L3A+XG5cdFx0XHRcdFx0XHQ8L1BhbmVsQm9keT5cblx0XHRcdFx0XHQ8L0luc3BlY3RvckNvbnRyb2xzPlxuXHRcdFx0XHQpO1xuXHRcdFx0fSxcblxuXHRcdFx0LyoqXG5cdFx0XHQgKiBHZXQgRmllbGQgc3R5bGVzIEpTWCBjb2RlLlxuXHRcdFx0ICpcblx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0ICpcblx0XHRcdCAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzICBCbG9jayBhdHRyaWJ1dGVzLlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGhhbmRsZXJzICAgIEJsb2NrIGV2ZW50IGhhbmRsZXJzLlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IHNpemVPcHRpb25zIFNpemUgc2VsZWN0b3Igb3B0aW9ucy5cblx0XHRcdCAqXG5cdFx0XHQgKiBAcmV0dXJucyB7SlNYLkVsZW1lbnR9IEZpZWxkIHN0eWxlcyBKU1ggY29kZS5cblx0XHRcdCAqL1xuXHRcdFx0Z2V0RmllbGRTdHlsZXM6IGZ1bmN0aW9uKCBhdHRyaWJ1dGVzLCBoYW5kbGVycywgc2l6ZU9wdGlvbnMgKSB7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbWF4LWxpbmVzLXBlci1mdW5jdGlvblxuXG5cdFx0XHRcdHJldHVybiAoXG5cdFx0XHRcdFx0PFBhbmVsQm9keSBjbGFzc05hbWU9eyBhcHAuZ2V0UGFuZWxDbGFzcyggYXR0cmlidXRlcyApIH0gdGl0bGU9eyBzdHJpbmdzLmZpZWxkX3N0eWxlcyB9PlxuXHRcdFx0XHRcdFx0PHAgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctcGFuZWwtbm90aWNlIHdwZm9ybXMtdXNlLW1vZGVybi1ub3RpY2VcIj5cblx0XHRcdFx0XHRcdFx0PHN0cm9uZz57IHN0cmluZ3MudXNlX21vZGVybl9ub3RpY2VfaGVhZCB9PC9zdHJvbmc+XG5cdFx0XHRcdFx0XHRcdHsgc3RyaW5ncy51c2VfbW9kZXJuX25vdGljZV90ZXh0IH0gPGEgaHJlZj17c3RyaW5ncy51c2VfbW9kZXJuX25vdGljZV9saW5rfSByZWw9XCJub3JlZmVycmVyXCIgdGFyZ2V0PVwiX2JsYW5rXCI+eyBzdHJpbmdzLmxlYXJuX21vcmUgfTwvYT5cblx0XHRcdFx0XHRcdDwvcD5cblxuXHRcdFx0XHRcdFx0PHAgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctcGFuZWwtbm90aWNlIHdwZm9ybXMtd2FybmluZyB3cGZvcm1zLWxlYWQtZm9ybS1ub3RpY2VcIiBzdHlsZT17eyBkaXNwbGF5OiAnbm9uZScgfX0+XG5cdFx0XHRcdFx0XHRcdDxzdHJvbmc+eyBzdHJpbmdzLmxlYWRfZm9ybXNfcGFuZWxfbm90aWNlX2hlYWQgfTwvc3Ryb25nPlxuXHRcdFx0XHRcdFx0XHR7IHN0cmluZ3MubGVhZF9mb3Jtc19wYW5lbF9ub3RpY2VfdGV4dCB9XG5cdFx0XHRcdFx0XHQ8L3A+XG5cblx0XHRcdFx0XHRcdDxGbGV4IGdhcD17NH0gYWxpZ249XCJmbGV4LXN0YXJ0XCIgY2xhc3NOYW1lPXsnd3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1mbGV4J30ganVzdGlmeT1cInNwYWNlLWJldHdlZW5cIj5cblx0XHRcdFx0XHRcdFx0PEZsZXhCbG9jaz5cblx0XHRcdFx0XHRcdFx0XHQ8U2VsZWN0Q29udHJvbFxuXHRcdFx0XHRcdFx0XHRcdFx0bGFiZWw9eyBzdHJpbmdzLnNpemUgfVxuXHRcdFx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmZpZWxkU2l6ZSB9XG5cdFx0XHRcdFx0XHRcdFx0XHRvcHRpb25zPXsgc2l6ZU9wdGlvbnMgfVxuXHRcdFx0XHRcdFx0XHRcdFx0b25DaGFuZ2U9eyB2YWx1ZSA9PiBoYW5kbGVycy5zdHlsZUF0dHJDaGFuZ2UoICdmaWVsZFNpemUnLCB2YWx1ZSApIH1cblx0XHRcdFx0XHRcdFx0XHQvPlxuXHRcdFx0XHRcdFx0XHQ8L0ZsZXhCbG9jaz5cblx0XHRcdFx0XHRcdFx0PEZsZXhCbG9jaz5cblx0XHRcdFx0XHRcdFx0XHQ8X19leHBlcmltZW50YWxVbml0Q29udHJvbFxuXHRcdFx0XHRcdFx0XHRcdFx0bGFiZWw9eyBzdHJpbmdzLmJvcmRlcl9yYWRpdXMgfVxuXHRcdFx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmZpZWxkQm9yZGVyUmFkaXVzIH1cblx0XHRcdFx0XHRcdFx0XHRcdGlzVW5pdFNlbGVjdFRhYmJhYmxlXG5cdFx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZT17IHZhbHVlID0+IGhhbmRsZXJzLnN0eWxlQXR0ckNoYW5nZSggJ2ZpZWxkQm9yZGVyUmFkaXVzJywgdmFsdWUgKSB9XG5cdFx0XHRcdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHRcdFx0PC9GbGV4QmxvY2s+XG5cdFx0XHRcdFx0XHQ8L0ZsZXg+XG5cblx0XHRcdFx0XHRcdDxkaXYgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1jb2xvci1waWNrZXJcIj5cblx0XHRcdFx0XHRcdFx0PGRpdiBjbGFzc05hbWU9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLWNvbnRyb2wtbGFiZWxcIj57IHN0cmluZ3MuY29sb3JzIH08L2Rpdj5cblx0XHRcdFx0XHRcdFx0PFBhbmVsQ29sb3JTZXR0aW5nc1xuXHRcdFx0XHRcdFx0XHRcdF9fZXhwZXJpbWVudGFsSXNSZW5kZXJlZEluU2lkZWJhclxuXHRcdFx0XHRcdFx0XHRcdGVuYWJsZUFscGhhXG5cdFx0XHRcdFx0XHRcdFx0c2hvd1RpdGxlPXsgZmFsc2UgfVxuXHRcdFx0XHRcdFx0XHRcdGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItY29sb3ItcGFuZWxcIlxuXHRcdFx0XHRcdFx0XHRcdGNvbG9yU2V0dGluZ3M9e1tcblx0XHRcdFx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0XHRcdFx0dmFsdWU6IGF0dHJpYnV0ZXMuZmllbGRCYWNrZ3JvdW5kQ29sb3IsXG5cdFx0XHRcdFx0XHRcdFx0XHRcdG9uQ2hhbmdlOiB2YWx1ZSA9PiBoYW5kbGVycy5zdHlsZUF0dHJDaGFuZ2UoICdmaWVsZEJhY2tncm91bmRDb2xvcicsIHZhbHVlICksXG5cdFx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsOiBzdHJpbmdzLmJhY2tncm91bmQsXG5cdFx0XHRcdFx0XHRcdFx0XHR9LFxuXHRcdFx0XHRcdFx0XHRcdFx0e1xuXHRcdFx0XHRcdFx0XHRcdFx0XHR2YWx1ZTogYXR0cmlidXRlcy5maWVsZEJvcmRlckNvbG9yLFxuXHRcdFx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZTogdmFsdWUgPT4gaGFuZGxlcnMuc3R5bGVBdHRyQ2hhbmdlKCAnZmllbGRCb3JkZXJDb2xvcicsIHZhbHVlICksXG5cdFx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsOiBzdHJpbmdzLmJvcmRlcixcblx0XHRcdFx0XHRcdFx0XHRcdH0sXG5cdFx0XHRcdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdFx0XHRcdHZhbHVlOiBhdHRyaWJ1dGVzLmZpZWxkVGV4dENvbG9yLFxuXHRcdFx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZTogdmFsdWUgPT4gaGFuZGxlcnMuc3R5bGVBdHRyQ2hhbmdlKCAnZmllbGRUZXh0Q29sb3InLCB2YWx1ZSApLFxuXHRcdFx0XHRcdFx0XHRcdFx0XHRsYWJlbDogc3RyaW5ncy50ZXh0LFxuXHRcdFx0XHRcdFx0XHRcdFx0fSxcblx0XHRcdFx0XHRcdFx0XHRdfVxuXHRcdFx0XHRcdFx0XHQvPlxuXHRcdFx0XHRcdFx0PC9kaXY+XG5cdFx0XHRcdFx0PC9QYW5lbEJvZHk+XG5cdFx0XHRcdCk7XG5cdFx0XHR9LFxuXG5cdFx0XHQvKipcblx0XHRcdCAqIEdldCBMYWJlbCBzdHlsZXMgSlNYIGNvZGUuXG5cdFx0XHQgKlxuXHRcdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0XHQgKlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXMgIEJsb2NrIGF0dHJpYnV0ZXMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gaGFuZGxlcnMgICAgQmxvY2sgZXZlbnQgaGFuZGxlcnMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gc2l6ZU9wdGlvbnMgU2l6ZSBzZWxlY3RvciBvcHRpb25zLlxuXHRcdFx0ICpcblx0XHRcdCAqIEByZXR1cm5zIHtKU1guRWxlbWVudH0gTGFiZWwgc3R5bGVzIEpTWCBjb2RlLlxuXHRcdFx0ICovXG5cdFx0XHRnZXRMYWJlbFN0eWxlczogZnVuY3Rpb24oIGF0dHJpYnV0ZXMsIGhhbmRsZXJzLCBzaXplT3B0aW9ucyApIHtcblxuXHRcdFx0XHRyZXR1cm4gKFxuXHRcdFx0XHRcdDxQYW5lbEJvZHkgY2xhc3NOYW1lPXsgYXBwLmdldFBhbmVsQ2xhc3MoIGF0dHJpYnV0ZXMgKSB9IHRpdGxlPXsgc3RyaW5ncy5sYWJlbF9zdHlsZXMgfT5cblx0XHRcdFx0XHRcdDxTZWxlY3RDb250cm9sXG5cdFx0XHRcdFx0XHRcdGxhYmVsPXsgc3RyaW5ncy5zaXplIH1cblx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmxhYmVsU2l6ZSB9XG5cdFx0XHRcdFx0XHRcdGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItZml4LWJvdHRvbS1tYXJnaW5cIlxuXHRcdFx0XHRcdFx0XHRvcHRpb25zPXsgc2l6ZU9wdGlvbnN9XG5cdFx0XHRcdFx0XHRcdG9uQ2hhbmdlPXsgdmFsdWUgPT4gaGFuZGxlcnMuc3R5bGVBdHRyQ2hhbmdlKCAnbGFiZWxTaXplJywgdmFsdWUgKSB9XG5cdFx0XHRcdFx0XHQvPlxuXG5cdFx0XHRcdFx0XHQ8ZGl2IGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItY29sb3ItcGlja2VyXCI+XG5cdFx0XHRcdFx0XHRcdDxkaXYgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1jb250cm9sLWxhYmVsXCI+eyBzdHJpbmdzLmNvbG9ycyB9PC9kaXY+XG5cdFx0XHRcdFx0XHRcdDxQYW5lbENvbG9yU2V0dGluZ3Ncblx0XHRcdFx0XHRcdFx0XHRfX2V4cGVyaW1lbnRhbElzUmVuZGVyZWRJblNpZGViYXJcblx0XHRcdFx0XHRcdFx0XHRlbmFibGVBbHBoYVxuXHRcdFx0XHRcdFx0XHRcdHNob3dUaXRsZT17IGZhbHNlIH1cblx0XHRcdFx0XHRcdFx0XHRjbGFzc05hbWU9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLWNvbG9yLXBhbmVsXCJcblx0XHRcdFx0XHRcdFx0XHRjb2xvclNldHRpbmdzPXtbXG5cdFx0XHRcdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdFx0XHRcdHZhbHVlOiBhdHRyaWJ1dGVzLmxhYmVsQ29sb3IsXG5cdFx0XHRcdFx0XHRcdFx0XHRcdG9uQ2hhbmdlOiB2YWx1ZSA9PiBoYW5kbGVycy5zdHlsZUF0dHJDaGFuZ2UoICdsYWJlbENvbG9yJywgdmFsdWUgKSxcblx0XHRcdFx0XHRcdFx0XHRcdFx0bGFiZWw6IHN0cmluZ3MubGFiZWwsXG5cdFx0XHRcdFx0XHRcdFx0XHR9LFxuXHRcdFx0XHRcdFx0XHRcdFx0e1xuXHRcdFx0XHRcdFx0XHRcdFx0XHR2YWx1ZTogYXR0cmlidXRlcy5sYWJlbFN1YmxhYmVsQ29sb3IsXG5cdFx0XHRcdFx0XHRcdFx0XHRcdG9uQ2hhbmdlOiB2YWx1ZSA9PiBoYW5kbGVycy5zdHlsZUF0dHJDaGFuZ2UoICdsYWJlbFN1YmxhYmVsQ29sb3InLCB2YWx1ZSApLFxuXHRcdFx0XHRcdFx0XHRcdFx0XHRsYWJlbDogc3RyaW5ncy5zdWJsYWJlbF9oaW50cy5yZXBsYWNlKCAnJmFtcDsnLCAnJicgKSxcblx0XHRcdFx0XHRcdFx0XHRcdH0sXG5cdFx0XHRcdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdFx0XHRcdHZhbHVlOiBhdHRyaWJ1dGVzLmxhYmVsRXJyb3JDb2xvcixcblx0XHRcdFx0XHRcdFx0XHRcdFx0b25DaGFuZ2U6IHZhbHVlID0+IGhhbmRsZXJzLnN0eWxlQXR0ckNoYW5nZSggJ2xhYmVsRXJyb3JDb2xvcicsIHZhbHVlICksXG5cdFx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsOiBzdHJpbmdzLmVycm9yX21lc3NhZ2UsXG5cdFx0XHRcdFx0XHRcdFx0XHR9LFxuXHRcdFx0XHRcdFx0XHRcdF19XG5cdFx0XHRcdFx0XHRcdC8+XG5cdFx0XHRcdFx0XHQ8L2Rpdj5cblx0XHRcdFx0XHQ8L1BhbmVsQm9keT5cblx0XHRcdFx0KTtcblx0XHRcdH0sXG5cblx0XHRcdC8qKlxuXHRcdFx0ICogR2V0IEJ1dHRvbiBzdHlsZXMgSlNYIGNvZGUuXG5cdFx0XHQgKlxuXHRcdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0XHQgKlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXMgIEJsb2NrIGF0dHJpYnV0ZXMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gaGFuZGxlcnMgICAgQmxvY2sgZXZlbnQgaGFuZGxlcnMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gc2l6ZU9wdGlvbnMgU2l6ZSBzZWxlY3RvciBvcHRpb25zLlxuXHRcdFx0ICpcblx0XHRcdCAqIEByZXR1cm5zIHtKU1guRWxlbWVudH0gIEJ1dHRvbiBzdHlsZXMgSlNYIGNvZGUuXG5cdFx0XHQgKi9cblx0XHRcdGdldEJ1dHRvblN0eWxlczogZnVuY3Rpb24oIGF0dHJpYnV0ZXMsIGhhbmRsZXJzLCBzaXplT3B0aW9ucyApIHtcblxuXHRcdFx0XHRyZXR1cm4gKFxuXHRcdFx0XHRcdDxQYW5lbEJvZHkgY2xhc3NOYW1lPXsgYXBwLmdldFBhbmVsQ2xhc3MoIGF0dHJpYnV0ZXMgKSB9IHRpdGxlPXsgc3RyaW5ncy5idXR0b25fc3R5bGVzIH0+XG5cdFx0XHRcdFx0XHQ8RmxleCBnYXA9ezR9IGFsaWduPVwiZmxleC1zdGFydFwiIGNsYXNzTmFtZT17J3dwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItZmxleCd9IGp1c3RpZnk9XCJzcGFjZS1iZXR3ZWVuXCI+XG5cdFx0XHRcdFx0XHRcdDxGbGV4QmxvY2s+XG5cdFx0XHRcdFx0XHRcdFx0PFNlbGVjdENvbnRyb2xcblx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsPXsgc3RyaW5ncy5zaXplIH1cblx0XHRcdFx0XHRcdFx0XHRcdHZhbHVlPXsgYXR0cmlidXRlcy5idXR0b25TaXplIH1cblx0XHRcdFx0XHRcdFx0XHRcdG9wdGlvbnM9eyBzaXplT3B0aW9ucyB9XG5cdFx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZT17IHZhbHVlID0+IGhhbmRsZXJzLnN0eWxlQXR0ckNoYW5nZSggJ2J1dHRvblNpemUnLCB2YWx1ZSApIH1cblx0XHRcdFx0XHRcdFx0XHQvPlxuXHRcdFx0XHRcdFx0XHQ8L0ZsZXhCbG9jaz5cblx0XHRcdFx0XHRcdFx0PEZsZXhCbG9jaz5cblx0XHRcdFx0XHRcdFx0XHQ8X19leHBlcmltZW50YWxVbml0Q29udHJvbFxuXHRcdFx0XHRcdFx0XHRcdFx0b25DaGFuZ2U9eyB2YWx1ZSA9PiBoYW5kbGVycy5zdHlsZUF0dHJDaGFuZ2UoICdidXR0b25Cb3JkZXJSYWRpdXMnLCB2YWx1ZSApIH1cblx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsPXsgc3RyaW5ncy5ib3JkZXJfcmFkaXVzIH1cblx0XHRcdFx0XHRcdFx0XHRcdGlzVW5pdFNlbGVjdFRhYmJhYmxlXG5cdFx0XHRcdFx0XHRcdFx0XHR2YWx1ZT17IGF0dHJpYnV0ZXMuYnV0dG9uQm9yZGVyUmFkaXVzIH0gLz5cblx0XHRcdFx0XHRcdFx0PC9GbGV4QmxvY2s+XG5cdFx0XHRcdFx0XHQ8L0ZsZXg+XG5cblx0XHRcdFx0XHRcdDxkaXYgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1jb2xvci1waWNrZXJcIj5cblx0XHRcdFx0XHRcdFx0PGRpdiBjbGFzc05hbWU9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLWNvbnRyb2wtbGFiZWxcIj57IHN0cmluZ3MuY29sb3JzIH08L2Rpdj5cblx0XHRcdFx0XHRcdFx0PFBhbmVsQ29sb3JTZXR0aW5nc1xuXHRcdFx0XHRcdFx0XHRcdF9fZXhwZXJpbWVudGFsSXNSZW5kZXJlZEluU2lkZWJhclxuXHRcdFx0XHRcdFx0XHRcdGVuYWJsZUFscGhhXG5cdFx0XHRcdFx0XHRcdFx0c2hvd1RpdGxlPXsgZmFsc2UgfVxuXHRcdFx0XHRcdFx0XHRcdGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItY29sb3ItcGFuZWxcIlxuXHRcdFx0XHRcdFx0XHRcdGNvbG9yU2V0dGluZ3M9e1tcblx0XHRcdFx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0XHRcdFx0dmFsdWU6IGF0dHJpYnV0ZXMuYnV0dG9uQmFja2dyb3VuZENvbG9yLFxuXHRcdFx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZTogdmFsdWUgPT4gaGFuZGxlcnMuc3R5bGVBdHRyQ2hhbmdlKCAnYnV0dG9uQmFja2dyb3VuZENvbG9yJywgdmFsdWUgKSxcblx0XHRcdFx0XHRcdFx0XHRcdFx0bGFiZWw6IHN0cmluZ3MuYmFja2dyb3VuZCxcblx0XHRcdFx0XHRcdFx0XHRcdH0sXG5cdFx0XHRcdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdFx0XHRcdHZhbHVlOiBhdHRyaWJ1dGVzLmJ1dHRvblRleHRDb2xvcixcblx0XHRcdFx0XHRcdFx0XHRcdFx0b25DaGFuZ2U6IHZhbHVlID0+IGhhbmRsZXJzLnN0eWxlQXR0ckNoYW5nZSggJ2J1dHRvblRleHRDb2xvcicsIHZhbHVlICksXG5cdFx0XHRcdFx0XHRcdFx0XHRcdGxhYmVsOiBzdHJpbmdzLnRleHQsXG5cdFx0XHRcdFx0XHRcdFx0XHR9LFxuXHRcdFx0XHRcdFx0XHRcdF19IC8+XG5cdFx0XHRcdFx0XHRcdDxkaXYgY2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1sZWdlbmQgd3Bmb3Jtcy1idXR0b24tY29sb3Itbm90aWNlXCI+XG5cdFx0XHRcdFx0XHRcdFx0eyBzdHJpbmdzLmJ1dHRvbl9jb2xvcl9ub3RpY2UgfVxuXHRcdFx0XHRcdFx0XHQ8L2Rpdj5cblx0XHRcdFx0XHRcdDwvZGl2PlxuXHRcdFx0XHRcdDwvUGFuZWxCb2R5PlxuXHRcdFx0XHQpO1xuXHRcdFx0fSxcblxuXHRcdFx0LyoqXG5cdFx0XHQgKiBHZXQgc3R5bGUgc2V0dGluZ3MgSlNYIGNvZGUuXG5cdFx0XHQgKlxuXHRcdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0XHQgKlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXMgIEJsb2NrIGF0dHJpYnV0ZXMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gaGFuZGxlcnMgICAgQmxvY2sgZXZlbnQgaGFuZGxlcnMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gc2l6ZU9wdGlvbnMgU2l6ZSBzZWxlY3RvciBvcHRpb25zLlxuXHRcdFx0ICpcblx0XHRcdCAqIEByZXR1cm5zIHtKU1guRWxlbWVudH0gSW5zcGVjdG9yIGNvbnRyb2xzIEpTWCBjb2RlLlxuXHRcdFx0ICovXG5cdFx0XHRnZXRTdHlsZVNldHRpbmdzOiBmdW5jdGlvbiggYXR0cmlidXRlcywgaGFuZGxlcnMsIHNpemVPcHRpb25zICkge1xuXG5cdFx0XHRcdHJldHVybiAoXG5cdFx0XHRcdFx0PEluc3BlY3RvckNvbnRyb2xzIGtleT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3Itc3R5bGUtc2V0dGluZ3NcIj5cblx0XHRcdFx0XHRcdHsgYXBwLmpzeFBhcnRzLmdldEZpZWxkU3R5bGVzKCBhdHRyaWJ1dGVzLCBoYW5kbGVycywgc2l6ZU9wdGlvbnMgKSB9XG5cdFx0XHRcdFx0XHR7IGFwcC5qc3hQYXJ0cy5nZXRMYWJlbFN0eWxlcyggYXR0cmlidXRlcywgaGFuZGxlcnMsIHNpemVPcHRpb25zICkgfVxuXHRcdFx0XHRcdFx0eyBhcHAuanN4UGFydHMuZ2V0QnV0dG9uU3R5bGVzKCBhdHRyaWJ1dGVzLCBoYW5kbGVycywgc2l6ZU9wdGlvbnMgKSB9XG5cdFx0XHRcdFx0PC9JbnNwZWN0b3JDb250cm9scz5cblx0XHRcdFx0KTtcblx0XHRcdH0sXG5cblx0XHRcdC8qKlxuXHRcdFx0ICogR2V0IGFkdmFuY2VkIHNldHRpbmdzIEpTWCBjb2RlLlxuXHRcdFx0ICpcblx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0ICpcblx0XHRcdCAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzIEJsb2NrIGF0dHJpYnV0ZXMuXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gaGFuZGxlcnMgICBCbG9jayBldmVudCBoYW5kbGVycy5cblx0XHRcdCAqXG5cdFx0XHQgKiBAcmV0dXJucyB7SlNYLkVsZW1lbnR9IEluc3BlY3RvciBhZHZhbmNlZCBjb250cm9scyBKU1ggY29kZS5cblx0XHRcdCAqL1xuXHRcdFx0Z2V0QWR2YW5jZWRTZXR0aW5nczogZnVuY3Rpb24oIGF0dHJpYnV0ZXMsIGhhbmRsZXJzICkge1xuXG5cdFx0XHRcdGNvbnN0IFsgaXNPcGVuLCBzZXRPcGVuIF0gPSB1c2VTdGF0ZSggZmFsc2UgKTtcblx0XHRcdFx0Y29uc3Qgb3Blbk1vZGFsID0gKCkgPT4gc2V0T3BlbiggdHJ1ZSApO1xuXHRcdFx0XHRjb25zdCBjbG9zZU1vZGFsID0gKCkgPT4gc2V0T3BlbiggZmFsc2UgKTtcblxuXHRcdFx0XHRyZXR1cm4gKFxuXHRcdFx0XHRcdDxJbnNwZWN0b3JBZHZhbmNlZENvbnRyb2xzPlxuXHRcdFx0XHRcdFx0PGRpdiBjbGFzc05hbWU9eyBhcHAuZ2V0UGFuZWxDbGFzcyggYXR0cmlidXRlcyApIH0+XG5cdFx0XHRcdFx0XHRcdDxUZXh0YXJlYUNvbnRyb2xcblx0XHRcdFx0XHRcdFx0XHRsYWJlbD17IHN0cmluZ3MuY29weV9wYXN0ZV9zZXR0aW5ncyB9XG5cdFx0XHRcdFx0XHRcdFx0cm93cz1cIjRcIlxuXHRcdFx0XHRcdFx0XHRcdHNwZWxsQ2hlY2s9XCJmYWxzZVwiXG5cdFx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmNvcHlQYXN0ZVZhbHVlIH1cblx0XHRcdFx0XHRcdFx0XHRvbkNoYW5nZT17IHZhbHVlID0+IGhhbmRsZXJzLnBhc3RlU2V0dGluZ3MoIHZhbHVlICkgfVxuXHRcdFx0XHRcdFx0XHQvPlxuXHRcdFx0XHRcdFx0XHQ8ZGl2IGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItbGVnZW5kXCIgZGFuZ2Vyb3VzbHlTZXRJbm5lckhUTUw9e3sgX19odG1sOiBzdHJpbmdzLmNvcHlfcGFzdGVfbm90aWNlIH19PjwvZGl2PlxuXG5cdFx0XHRcdFx0XHRcdDxCdXR0b24gY2xhc3NOYW1lPSd3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLXJlc2V0LWJ1dHRvbicgb25DbGljaz17IG9wZW5Nb2RhbCB9Pnsgc3RyaW5ncy5yZXNldF9zdHlsZV9zZXR0aW5ncyB9PC9CdXR0b24+XG5cdFx0XHRcdFx0XHQ8L2Rpdj5cblxuXHRcdFx0XHRcdFx0eyBpc09wZW4gJiYgKFxuXHRcdFx0XHRcdFx0XHQ8TW9kYWwgIGNsYXNzTmFtZT1cIndwZm9ybXMtZ3V0ZW5iZXJnLW1vZGFsXCJcblx0XHRcdFx0XHRcdFx0XHR0aXRsZT17IHN0cmluZ3MucmVzZXRfc3R5bGVfc2V0dGluZ3N9XG5cdFx0XHRcdFx0XHRcdFx0b25SZXF1ZXN0Q2xvc2U9eyBjbG9zZU1vZGFsIH0+XG5cblx0XHRcdFx0XHRcdFx0XHQ8cD57IHN0cmluZ3MucmVzZXRfc2V0dGluZ3NfY29uZmlybV90ZXh0IH08L3A+XG5cblx0XHRcdFx0XHRcdFx0XHQ8RmxleCBnYXA9ezN9IGFsaWduPVwiY2VudGVyXCIganVzdGlmeT1cImZsZXgtZW5kXCI+XG5cdFx0XHRcdFx0XHRcdFx0XHQ8QnV0dG9uIGlzU2Vjb25kYXJ5IG9uQ2xpY2s9eyBjbG9zZU1vZGFsIH0+XG5cdFx0XHRcdFx0XHRcdFx0XHRcdHtzdHJpbmdzLmJ0bl9ub31cblx0XHRcdFx0XHRcdFx0XHRcdDwvQnV0dG9uPlxuXG5cdFx0XHRcdFx0XHRcdFx0XHQ8QnV0dG9uIGlzUHJpbWFyeSBvbkNsaWNrPXsgKCkgPT4ge1xuXHRcdFx0XHRcdFx0XHRcdFx0XHRjbG9zZU1vZGFsKCk7XG5cdFx0XHRcdFx0XHRcdFx0XHRcdGhhbmRsZXJzLnJlc2V0U2V0dGluZ3MoKTtcblx0XHRcdFx0XHRcdFx0XHRcdH0gfT5cblx0XHRcdFx0XHRcdFx0XHRcdFx0eyBzdHJpbmdzLmJ0bl95ZXNfcmVzZXQgfVxuXHRcdFx0XHRcdFx0XHRcdFx0PC9CdXR0b24+XG5cdFx0XHRcdFx0XHRcdFx0PC9GbGV4PlxuXHRcdFx0XHRcdFx0XHQ8L01vZGFsPlxuXHRcdFx0XHRcdFx0KSB9XG5cdFx0XHRcdFx0PC9JbnNwZWN0b3JBZHZhbmNlZENvbnRyb2xzPlxuXHRcdFx0XHQpO1xuXHRcdFx0fSxcblxuXHRcdFx0LyoqXG5cdFx0XHQgKiBHZXQgYmxvY2sgY29udGVudCBKU1ggY29kZS5cblx0XHRcdCAqXG5cdFx0XHQgKiBAc2luY2UgMS44LjFcblx0XHRcdCAqXG5cdFx0XHQgKiBAcGFyYW0ge29iamVjdH0gcHJvcHMgQmxvY2sgcHJvcGVydGllcy5cblx0XHRcdCAqXG5cdFx0XHQgKiBAcmV0dXJucyB7SlNYLkVsZW1lbnR9IEJsb2NrIGNvbnRlbnQgSlNYIGNvZGUuXG5cdFx0XHQgKi9cblx0XHRcdGdldEJsb2NrRm9ybUNvbnRlbnQ6IGZ1bmN0aW9uKCBwcm9wcyApIHtcblxuXHRcdFx0XHRpZiAoIHRyaWdnZXJTZXJ2ZXJSZW5kZXIgKSB7XG5cblx0XHRcdFx0XHRyZXR1cm4gKFxuXHRcdFx0XHRcdFx0PFNlcnZlclNpZGVSZW5kZXJcblx0XHRcdFx0XHRcdFx0a2V5PVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1zZXJ2ZXItc2lkZS1yZW5kZXJlclwiXG5cdFx0XHRcdFx0XHRcdGJsb2NrPVwid3Bmb3Jtcy9mb3JtLXNlbGVjdG9yXCJcblx0XHRcdFx0XHRcdFx0YXR0cmlidXRlcz17IHByb3BzLmF0dHJpYnV0ZXMgfVxuXHRcdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHQpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0Y29uc3QgY2xpZW50SWQgPSBwcm9wcy5jbGllbnRJZDtcblx0XHRcdFx0Y29uc3QgYmxvY2sgPSBhcHAuZ2V0QmxvY2tDb250YWluZXIoIHByb3BzICk7XG5cblx0XHRcdFx0Ly8gSW4gdGhlIGNhc2Ugb2YgZW1wdHkgY29udGVudCwgdXNlIHNlcnZlciBzaWRlIHJlbmRlcmVyLlxuXHRcdFx0XHQvLyBUaGlzIGhhcHBlbnMgd2hlbiB0aGUgYmxvY2sgaXMgZHVwbGljYXRlZCBvciBjb252ZXJ0ZWQgdG8gYSByZXVzYWJsZSBibG9jay5cblx0XHRcdFx0aWYgKCAhIGJsb2NrIHx8ICEgYmxvY2suaW5uZXJIVE1MICkge1xuXHRcdFx0XHRcdHRyaWdnZXJTZXJ2ZXJSZW5kZXIgPSB0cnVlO1xuXG5cdFx0XHRcdFx0cmV0dXJuIGFwcC5qc3hQYXJ0cy5nZXRCbG9ja0Zvcm1Db250ZW50KCBwcm9wcyApO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0YmxvY2tzWyBjbGllbnRJZCBdID0gYmxvY2tzWyBjbGllbnRJZCBdIHx8IHt9O1xuXHRcdFx0XHRibG9ja3NbIGNsaWVudElkIF0uYmxvY2tIVE1MID0gYmxvY2suaW5uZXJIVE1MO1xuXHRcdFx0XHRibG9ja3NbIGNsaWVudElkIF0ubG9hZGVkRm9ybUlkID0gcHJvcHMuYXR0cmlidXRlcy5mb3JtSWQ7XG5cblx0XHRcdFx0cmV0dXJuIChcblx0XHRcdFx0XHQ8RnJhZ21lbnQga2V5PVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1mcmFnbWVudC1mb3JtLWh0bWxcIj5cblx0XHRcdFx0XHRcdDxkaXYgZGFuZ2Vyb3VzbHlTZXRJbm5lckhUTUw9e3sgX19odG1sOiBibG9ja3NbIGNsaWVudElkIF0uYmxvY2tIVE1MIH19IC8+XG5cdFx0XHRcdFx0PC9GcmFnbWVudD5cblx0XHRcdFx0KTtcblx0XHRcdH0sXG5cblx0XHRcdC8qKlxuXHRcdFx0ICogR2V0IGJsb2NrIHByZXZpZXcgSlNYIGNvZGUuXG5cdFx0XHQgKlxuXHRcdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0XHQgKlxuXHRcdFx0ICogQHJldHVybnMge0pTWC5FbGVtZW50fSBCbG9jayBwcmV2aWV3IEpTWCBjb2RlLlxuXHRcdFx0ICovXG5cdFx0XHRnZXRCbG9ja1ByZXZpZXc6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRcdHJldHVybiAoXG5cdFx0XHRcdFx0PEZyYWdtZW50XG5cdFx0XHRcdFx0XHRrZXk9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLWZyYWdtZW50LWJsb2NrLXByZXZpZXdcIj5cblx0XHRcdFx0XHRcdDxpbWcgc3JjPXsgd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5ibG9ja19wcmV2aWV3X3VybCB9IHN0eWxlPXt7IHdpZHRoOiAnMTAwJScgfX0gLz5cblx0XHRcdFx0XHQ8L0ZyYWdtZW50PlxuXHRcdFx0XHQpO1xuXHRcdFx0fSxcblxuXHRcdFx0LyoqXG5cdFx0XHQgKiBHZXQgYmxvY2sgcGxhY2Vob2xkZXIgKGZvcm0gc2VsZWN0b3IpIEpTWCBjb2RlLlxuXHRcdFx0ICpcblx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0ICpcblx0XHRcdCAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzICBCbG9jayBhdHRyaWJ1dGVzLlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGhhbmRsZXJzICAgIEJsb2NrIGV2ZW50IGhhbmRsZXJzLlxuXHRcdFx0ICogQHBhcmFtIHtvYmplY3R9IGZvcm1PcHRpb25zIEZvcm0gc2VsZWN0b3Igb3B0aW9ucy5cblx0XHRcdCAqXG5cdFx0XHQgKiBAcmV0dXJucyB7SlNYLkVsZW1lbnR9IEJsb2NrIHBsYWNlaG9sZGVyIEpTWCBjb2RlLlxuXHRcdFx0ICovXG5cdFx0XHRnZXRCbG9ja1BsYWNlaG9sZGVyOiBmdW5jdGlvbiggYXR0cmlidXRlcywgaGFuZGxlcnMsIGZvcm1PcHRpb25zICkge1xuXG5cdFx0XHRcdHJldHVybiAoXG5cdFx0XHRcdFx0PFBsYWNlaG9sZGVyXG5cdFx0XHRcdFx0XHRrZXk9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLXdyYXBcIlxuXHRcdFx0XHRcdFx0Y2xhc3NOYW1lPVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci13cmFwXCI+XG5cdFx0XHRcdFx0XHQ8aW1nIHNyYz17d3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5sb2dvX3VybH0gLz5cblx0XHRcdFx0XHRcdDxoMz57IHN0cmluZ3MudGl0bGUgfTwvaDM+XG5cdFx0XHRcdFx0XHQ8U2VsZWN0Q29udHJvbFxuXHRcdFx0XHRcdFx0XHRrZXk9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLXNlbGVjdC1jb250cm9sXCJcblx0XHRcdFx0XHRcdFx0dmFsdWU9eyBhdHRyaWJ1dGVzLmZvcm1JZCB9XG5cdFx0XHRcdFx0XHRcdG9wdGlvbnM9eyBmb3JtT3B0aW9ucyB9XG5cdFx0XHRcdFx0XHRcdG9uQ2hhbmdlPXsgdmFsdWUgPT4gaGFuZGxlcnMuYXR0ckNoYW5nZSggJ2Zvcm1JZCcsIHZhbHVlICkgfVxuXHRcdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHQ8L1BsYWNlaG9sZGVyPlxuXHRcdFx0XHQpO1xuXHRcdFx0fSxcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogR2V0IFN0eWxlIFNldHRpbmdzIHBhbmVsIGNsYXNzLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlcyBCbG9jayBhdHRyaWJ1dGVzLlxuXHRcdCAqXG5cdFx0ICogQHJldHVybnMge3N0cmluZ30gU3R5bGUgU2V0dGluZ3MgcGFuZWwgY2xhc3MuXG5cdFx0ICovXG5cdFx0Z2V0UGFuZWxDbGFzczogZnVuY3Rpb24oIGF0dHJpYnV0ZXMgKSB7XG5cblx0XHRcdGxldCBjc3NDbGFzcyA9ICd3cGZvcm1zLWd1dGVuYmVyZy1wYW5lbCB3cGZvcm1zLWJsb2NrLXNldHRpbmdzLScgKyBhdHRyaWJ1dGVzLmNsaWVudElkO1xuXG5cdFx0XHRpZiAoICEgYXBwLmlzRnVsbFN0eWxpbmdFbmFibGVkKCkgKSB7XG5cdFx0XHRcdGNzc0NsYXNzICs9ICcgZGlzYWJsZWRfcGFuZWwnO1xuXHRcdFx0fVxuXG5cdFx0XHRyZXR1cm4gY3NzQ2xhc3M7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIERldGVybWluZSB3aGV0aGVyIHRoZSBmdWxsIHN0eWxpbmcgaXMgZW5hYmxlZC5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHJldHVybnMge2Jvb2xlYW59IFdoZXRoZXIgdGhlIGZ1bGwgc3R5bGluZyBpcyBlbmFibGVkLlxuXHRcdCAqL1xuXHRcdGlzRnVsbFN0eWxpbmdFbmFibGVkOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0cmV0dXJuIHdwZm9ybXNfZ3V0ZW5iZXJnX2Zvcm1fc2VsZWN0b3IuaXNfbW9kZXJuX21hcmt1cCAmJiB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLmlzX2Z1bGxfc3R5bGluZztcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogR2V0IGJsb2NrIGNvbnRhaW5lciBET00gZWxlbWVudC5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtvYmplY3R9IHByb3BzIEJsb2NrIHByb3BlcnRpZXMuXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7RWxlbWVudH0gQmxvY2sgY29udGFpbmVyLlxuXHRcdCAqL1xuXHRcdGdldEJsb2NrQ29udGFpbmVyOiBmdW5jdGlvbiggcHJvcHMgKSB7XG5cblx0XHRcdGNvbnN0IGJsb2NrU2VsZWN0b3IgPSBgI2Jsb2NrLSR7cHJvcHMuY2xpZW50SWR9ID4gZGl2YDtcblx0XHRcdGxldCBibG9jayA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoIGJsb2NrU2VsZWN0b3IgKTtcblxuXHRcdFx0Ly8gRm9yIEZTRSAvIEd1dGVuYmVyZyBwbHVnaW4gd2UgbmVlZCB0byB0YWtlIGEgbG9vayBpbnNpZGUgdGhlIGlmcmFtZS5cblx0XHRcdGlmICggISBibG9jayApIHtcblx0XHRcdFx0Y29uc3QgZWRpdG9yQ2FudmFzID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvciggJ2lmcmFtZVtuYW1lPVwiZWRpdG9yLWNhbnZhc1wiXScgKTtcblxuXHRcdFx0XHRibG9jayA9IGVkaXRvckNhbnZhcyAmJiBlZGl0b3JDYW52YXMuY29udGVudFdpbmRvdy5kb2N1bWVudC5xdWVyeVNlbGVjdG9yKCBibG9ja1NlbGVjdG9yICk7XG5cdFx0XHR9XG5cblx0XHRcdHJldHVybiBibG9jaztcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogR2V0IHNldHRpbmdzIGZpZWxkcyBldmVudCBoYW5kbGVycy5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtvYmplY3R9IHByb3BzIEJsb2NrIHByb3BlcnRpZXMuXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7b2JqZWN0fSBPYmplY3QgdGhhdCBjb250YWlucyBldmVudCBoYW5kbGVycyBmb3IgdGhlIHNldHRpbmdzIGZpZWxkcy5cblx0XHQgKi9cblx0XHRnZXRTZXR0aW5nc0ZpZWxkc0hhbmRsZXJzOiBmdW5jdGlvbiggcHJvcHMgKSB7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbWF4LWxpbmVzLXBlci1mdW5jdGlvblxuXG5cdFx0XHRyZXR1cm4ge1xuXG5cdFx0XHRcdC8qKlxuXHRcdFx0XHQgKiBGaWVsZCBzdHlsZSBhdHRyaWJ1dGUgY2hhbmdlIGV2ZW50IGhhbmRsZXIuXG5cdFx0XHRcdCAqXG5cdFx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0XHQgKlxuXHRcdFx0XHQgKiBAcGFyYW0ge3N0cmluZ30gYXR0cmlidXRlIEF0dHJpYnV0ZSBuYW1lLlxuXHRcdFx0XHQgKiBAcGFyYW0ge3N0cmluZ30gdmFsdWUgICAgIE5ldyBhdHRyaWJ1dGUgdmFsdWUuXG5cdFx0XHRcdCAqL1xuXHRcdFx0XHRzdHlsZUF0dHJDaGFuZ2U6IGZ1bmN0aW9uKCBhdHRyaWJ1dGUsIHZhbHVlICkge1xuXG5cdFx0XHRcdFx0Y29uc3QgYmxvY2sgPSBhcHAuZ2V0QmxvY2tDb250YWluZXIoIHByb3BzICksXG5cdFx0XHRcdFx0XHRjb250YWluZXIgPSBibG9jay5xdWVyeVNlbGVjdG9yKCBgI3dwZm9ybXMtJHtwcm9wcy5hdHRyaWJ1dGVzLmZvcm1JZH1gICksXG5cdFx0XHRcdFx0XHRwcm9wZXJ0eSA9IGF0dHJpYnV0ZS5yZXBsYWNlKCAvW0EtWl0vZywgbGV0dGVyID0+IGAtJHtsZXR0ZXIudG9Mb3dlckNhc2UoKX1gICksXG5cdFx0XHRcdFx0XHRzZXRBdHRyID0ge307XG5cblx0XHRcdFx0XHRpZiAoIGNvbnRhaW5lciApIHtcblx0XHRcdFx0XHRcdHN3aXRjaCAoIHByb3BlcnR5ICkge1xuXHRcdFx0XHRcdFx0XHRjYXNlICdmaWVsZC1zaXplJzpcblx0XHRcdFx0XHRcdFx0Y2FzZSAnbGFiZWwtc2l6ZSc6XG5cdFx0XHRcdFx0XHRcdGNhc2UgJ2J1dHRvbi1zaXplJzpcblx0XHRcdFx0XHRcdFx0XHRmb3IgKCBjb25zdCBrZXkgaW4gc2l6ZXNbIHByb3BlcnR5IF1bIHZhbHVlIF0gKSB7XG5cdFx0XHRcdFx0XHRcdFx0XHRjb250YWluZXIuc3R5bGUuc2V0UHJvcGVydHkoXG5cdFx0XHRcdFx0XHRcdFx0XHRcdGAtLXdwZm9ybXMtJHtwcm9wZXJ0eX0tJHtrZXl9YCxcblx0XHRcdFx0XHRcdFx0XHRcdFx0c2l6ZXNbIHByb3BlcnR5IF1bIHZhbHVlIF1bIGtleSBdLFxuXHRcdFx0XHRcdFx0XHRcdFx0KTtcblx0XHRcdFx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHRcdFx0XHRicmVhaztcblxuXHRcdFx0XHRcdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHRcdFx0XHRcdGNvbnRhaW5lci5zdHlsZS5zZXRQcm9wZXJ0eSggYC0td3Bmb3Jtcy0ke3Byb3BlcnR5fWAsIHZhbHVlICk7XG5cdFx0XHRcdFx0XHR9XG5cdFx0XHRcdFx0fVxuXG5cdFx0XHRcdFx0c2V0QXR0clsgYXR0cmlidXRlIF0gPSB2YWx1ZTtcblxuXHRcdFx0XHRcdHByb3BzLnNldEF0dHJpYnV0ZXMoIHNldEF0dHIgKTtcblxuXHRcdFx0XHRcdHRyaWdnZXJTZXJ2ZXJSZW5kZXIgPSBmYWxzZTtcblxuXHRcdFx0XHRcdHRoaXMudXBkYXRlQ29weVBhc3RlQ29udGVudCgpO1xuXG5cdFx0XHRcdFx0JCggd2luZG93ICkudHJpZ2dlciggJ3dwZm9ybXNGb3JtU2VsZWN0b3JTdHlsZUF0dHJDaGFuZ2UnLCBbIGJsb2NrLCBwcm9wcywgYXR0cmlidXRlLCB2YWx1ZSBdICk7XG5cdFx0XHRcdH0sXG5cblx0XHRcdFx0LyoqXG5cdFx0XHRcdCAqIEZpZWxkIHJlZ3VsYXIgYXR0cmlidXRlIGNoYW5nZSBldmVudCBoYW5kbGVyLlxuXHRcdFx0XHQgKlxuXHRcdFx0XHQgKiBAc2luY2UgMS44LjFcblx0XHRcdFx0ICpcblx0XHRcdFx0ICogQHBhcmFtIHtzdHJpbmd9IGF0dHJpYnV0ZSBBdHRyaWJ1dGUgbmFtZS5cblx0XHRcdFx0ICogQHBhcmFtIHtzdHJpbmd9IHZhbHVlICAgICBOZXcgYXR0cmlidXRlIHZhbHVlLlxuXHRcdFx0XHQgKi9cblx0XHRcdFx0YXR0ckNoYW5nZTogZnVuY3Rpb24oIGF0dHJpYnV0ZSwgdmFsdWUgKSB7XG5cblx0XHRcdFx0XHRjb25zdCBzZXRBdHRyID0ge307XG5cblx0XHRcdFx0XHRzZXRBdHRyWyBhdHRyaWJ1dGUgXSA9IHZhbHVlO1xuXG5cdFx0XHRcdFx0cHJvcHMuc2V0QXR0cmlidXRlcyggc2V0QXR0ciApO1xuXG5cdFx0XHRcdFx0dHJpZ2dlclNlcnZlclJlbmRlciA9IHRydWU7XG5cblx0XHRcdFx0XHR0aGlzLnVwZGF0ZUNvcHlQYXN0ZUNvbnRlbnQoKTtcblx0XHRcdFx0fSxcblxuXHRcdFx0XHQvKipcblx0XHRcdFx0ICogUmVzZXQgRm9ybSBTdHlsZXMgc2V0dGluZ3MgdG8gZGVmYXVsdHMuXG5cdFx0XHRcdCAqXG5cdFx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0XHQgKi9cblx0XHRcdFx0cmVzZXRTZXR0aW5nczogZnVuY3Rpb24oKSB7XG5cblx0XHRcdFx0XHRmb3IgKCBsZXQga2V5IGluIGRlZmF1bHRTdHlsZVNldHRpbmdzICkge1xuXHRcdFx0XHRcdFx0dGhpcy5zdHlsZUF0dHJDaGFuZ2UoIGtleSwgZGVmYXVsdFN0eWxlU2V0dGluZ3NbIGtleSBdICk7XG5cdFx0XHRcdFx0fVxuXHRcdFx0XHR9LFxuXG5cdFx0XHRcdC8qKlxuXHRcdFx0XHQgKiBVcGRhdGUgY29udGVudCBvZiB0aGUgXCJDb3B5L1Bhc3RlXCIgZmllbGRzLlxuXHRcdFx0XHQgKlxuXHRcdFx0XHQgKiBAc2luY2UgMS44LjFcblx0XHRcdFx0ICovXG5cdFx0XHRcdHVwZGF0ZUNvcHlQYXN0ZUNvbnRlbnQ6IGZ1bmN0aW9uKCkge1xuXG5cdFx0XHRcdFx0bGV0IGNvbnRlbnQgPSB7fTtcblx0XHRcdFx0XHRsZXQgYXR0cyA9IHdwLmRhdGEuc2VsZWN0KCAnY29yZS9ibG9jay1lZGl0b3InICkuZ2V0QmxvY2tBdHRyaWJ1dGVzKCBwcm9wcy5jbGllbnRJZCApO1xuXG5cdFx0XHRcdFx0Zm9yICggbGV0IGtleSBpbiBkZWZhdWx0U3R5bGVTZXR0aW5ncyApIHtcblx0XHRcdFx0XHRcdGNvbnRlbnRba2V5XSA9IGF0dHNbIGtleSBdO1xuXHRcdFx0XHRcdH1cblxuXHRcdFx0XHRcdHByb3BzLnNldEF0dHJpYnV0ZXMoIHsgJ2NvcHlQYXN0ZVZhbHVlJzogSlNPTi5zdHJpbmdpZnkoIGNvbnRlbnQgKSB9ICk7XG5cdFx0XHRcdH0sXG5cblx0XHRcdFx0LyoqXG5cdFx0XHRcdCAqIFBhc3RlIHNldHRpbmdzIGhhbmRsZXIuXG5cdFx0XHRcdCAqXG5cdFx0XHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdFx0XHQgKlxuXHRcdFx0XHQgKiBAcGFyYW0ge3N0cmluZ30gdmFsdWUgTmV3IGF0dHJpYnV0ZSB2YWx1ZS5cblx0XHRcdFx0ICovXG5cdFx0XHRcdHBhc3RlU2V0dGluZ3M6IGZ1bmN0aW9uKCB2YWx1ZSApIHtcblxuXHRcdFx0XHRcdGxldCBwYXN0ZUF0dHJpYnV0ZXMgPSBhcHAucGFyc2VWYWxpZGF0ZUpzb24oIHZhbHVlICk7XG5cblx0XHRcdFx0XHRpZiAoICEgcGFzdGVBdHRyaWJ1dGVzICkge1xuXG5cdFx0XHRcdFx0XHR3cC5kYXRhLmRpc3BhdGNoKCAnY29yZS9ub3RpY2VzJyApLmNyZWF0ZUVycm9yTm90aWNlKFxuXHRcdFx0XHRcdFx0XHRzdHJpbmdzLmNvcHlfcGFzdGVfZXJyb3IsXG5cdFx0XHRcdFx0XHRcdHsgaWQ6ICd3cGZvcm1zLWpzb24tcGFyc2UtZXJyb3InIH1cblx0XHRcdFx0XHRcdCk7XG5cblx0XHRcdFx0XHRcdHRoaXMudXBkYXRlQ29weVBhc3RlQ29udGVudCgpO1xuXG5cdFx0XHRcdFx0XHRyZXR1cm47XG5cdFx0XHRcdFx0fVxuXG5cdFx0XHRcdFx0cGFzdGVBdHRyaWJ1dGVzLmNvcHlQYXN0ZVZhbHVlID0gdmFsdWU7XG5cblx0XHRcdFx0XHRwcm9wcy5zZXRBdHRyaWJ1dGVzKCBwYXN0ZUF0dHJpYnV0ZXMgKTtcblxuXHRcdFx0XHRcdHRyaWdnZXJTZXJ2ZXJSZW5kZXIgPSB0cnVlO1xuXHRcdFx0XHR9LFxuXHRcdFx0fTtcblx0XHR9LFxuXG5cdFx0LyoqXG5cdFx0ICogUGFyc2UgYW5kIHZhbGlkYXRlIEpTT04gc3RyaW5nLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcGFyYW0ge3N0cmluZ30gdmFsdWUgSlNPTiBzdHJpbmcuXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7Ym9vbGVhbnxvYmplY3R9IFBhcnNlZCBKU09OIG9iamVjdCBPUiBmYWxzZSBvbiBlcnJvci5cblx0XHQgKi9cblx0XHRwYXJzZVZhbGlkYXRlSnNvbjogZnVuY3Rpb24oIHZhbHVlICkge1xuXG5cdFx0XHRpZiAoIHR5cGVvZiB2YWx1ZSAhPT0gJ3N0cmluZycgKSB7XG5cdFx0XHRcdHJldHVybiBmYWxzZTtcblx0XHRcdH1cblxuXHRcdFx0bGV0IGF0dHM7XG5cblx0XHRcdHRyeSB7XG5cdFx0XHRcdGF0dHMgPSBKU09OLnBhcnNlKCB2YWx1ZSApO1xuXHRcdFx0fSBjYXRjaCAoIGVycm9yICkge1xuXHRcdFx0XHRhdHRzID0gZmFsc2U7XG5cdFx0XHR9XG5cblx0XHRcdHJldHVybiBhdHRzO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBHZXQgV1BGb3JtcyBpY29uIERPTSBlbGVtZW50LlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7RE9NLmVsZW1lbnR9IFdQRm9ybXMgaWNvbiBET00gZWxlbWVudC5cblx0XHQgKi9cblx0XHRnZXRJY29uOiBmdW5jdGlvbigpIHtcblxuXHRcdFx0cmV0dXJuIGNyZWF0ZUVsZW1lbnQoXG5cdFx0XHRcdCdzdmcnLFxuXHRcdFx0XHR7IHdpZHRoOiAyMCwgaGVpZ2h0OiAyMCwgdmlld0JveDogJzAgMCA2MTIgNjEyJywgY2xhc3NOYW1lOiAnZGFzaGljb24nIH0sXG5cdFx0XHRcdGNyZWF0ZUVsZW1lbnQoXG5cdFx0XHRcdFx0J3BhdGgnLFxuXHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdGZpbGw6ICdjdXJyZW50Q29sb3InLFxuXHRcdFx0XHRcdFx0ZDogJ001NDQsMEg2OEMzMC40NDUsMCwwLDMwLjQ0NSwwLDY4djQ3NmMwLDM3LjU1NiwzMC40NDUsNjgsNjgsNjhoNDc2YzM3LjU1NiwwLDY4LTMwLjQ0NCw2OC02OFY2OCBDNjEyLDMwLjQ0NSw1ODEuNTU2LDAsNTQ0LDB6IE00NjQuNDQsNjhMMzg3LjYsMTIwLjAyTDMyMy4zNCw2OEg0NjQuNDR6IE0yODguNjYsNjhsLTY0LjI2LDUyLjAyTDE0Ny41Niw2OEgyODguNjZ6IE01NDQsNTQ0SDY4IFY2OGgyMi4xbDEzNiw5Mi4xNGw3OS45LTY0LjZsNzkuNTYsNjQuNmwxMzYtOTIuMTRINTQ0VjU0NHogTTExNC4yNCwyNjMuMTZoOTUuODh2LTQ4LjI4aC05NS44OFYyNjMuMTZ6IE0xMTQuMjQsMzYwLjRoOTUuODggdi00OC42MmgtOTUuODhWMzYwLjR6IE0yNDIuNzYsMzYwLjRoMjU1di00OC42MmgtMjU1VjM2MC40TDI0Mi43NiwzNjAuNHogTTI0Mi43NiwyNjMuMTZoMjU1di00OC4yOGgtMjU1VjI2My4xNkwyNDIuNzYsMjYzLjE2eiBNMzY4LjIyLDQ1Ny4zaDEyOS41NFY0MDhIMzY4LjIyVjQ1Ny4zeicsXG5cdFx0XHRcdFx0fSxcblx0XHRcdFx0KSxcblx0XHRcdCk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEdldCBibG9jayBhdHRyaWJ1dGVzLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7b2JqZWN0fSBCbG9jayBhdHRyaWJ1dGVzLlxuXHRcdCAqL1xuXHRcdGdldEJsb2NrQXR0cmlidXRlczogZnVuY3Rpb24oKSB7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbWF4LWxpbmVzLXBlci1mdW5jdGlvblxuXG5cdFx0XHRyZXR1cm4ge1xuXHRcdFx0XHRjbGllbnRJZDoge1xuXHRcdFx0XHRcdHR5cGU6ICdzdHJpbmcnLFxuXHRcdFx0XHRcdGRlZmF1bHQ6ICcnLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRmb3JtSWQ6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5mb3JtSWQsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGRpc3BsYXlUaXRsZToge1xuXHRcdFx0XHRcdHR5cGU6ICdib29sZWFuJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5kaXNwbGF5VGl0bGUsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGRpc3BsYXlEZXNjOiB7XG5cdFx0XHRcdFx0dHlwZTogJ2Jvb2xlYW4nLFxuXHRcdFx0XHRcdGRlZmF1bHQ6IGRlZmF1bHRzLmRpc3BsYXlEZXNjLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRwcmV2aWV3OiB7XG5cdFx0XHRcdFx0dHlwZTogJ2Jvb2xlYW4nLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRmaWVsZFNpemU6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5maWVsZFNpemUsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGZpZWxkQm9yZGVyUmFkaXVzOiB7XG5cdFx0XHRcdFx0dHlwZTogJ3N0cmluZycsXG5cdFx0XHRcdFx0ZGVmYXVsdDogZGVmYXVsdHMuZmllbGRCb3JkZXJSYWRpdXMsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGZpZWxkQmFja2dyb3VuZENvbG9yOiB7XG5cdFx0XHRcdFx0dHlwZTogJ3N0cmluZycsXG5cdFx0XHRcdFx0ZGVmYXVsdDogZGVmYXVsdHMuZmllbGRCYWNrZ3JvdW5kQ29sb3IsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGZpZWxkQm9yZGVyQ29sb3I6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5maWVsZEJvcmRlckNvbG9yLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRmaWVsZFRleHRDb2xvcjoge1xuXHRcdFx0XHRcdHR5cGU6ICdzdHJpbmcnLFxuXHRcdFx0XHRcdGRlZmF1bHQ6IGRlZmF1bHRzLmZpZWxkVGV4dENvbG9yLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRsYWJlbFNpemU6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5sYWJlbFNpemUsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGxhYmVsQ29sb3I6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5sYWJlbENvbG9yLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRsYWJlbFN1YmxhYmVsQ29sb3I6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5sYWJlbFN1YmxhYmVsQ29sb3IsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGxhYmVsRXJyb3JDb2xvcjoge1xuXHRcdFx0XHRcdHR5cGU6ICdzdHJpbmcnLFxuXHRcdFx0XHRcdGRlZmF1bHQ6IGRlZmF1bHRzLmxhYmVsRXJyb3JDb2xvcixcblx0XHRcdFx0fSxcblx0XHRcdFx0YnV0dG9uU2l6ZToge1xuXHRcdFx0XHRcdHR5cGU6ICdzdHJpbmcnLFxuXHRcdFx0XHRcdGRlZmF1bHQ6IGRlZmF1bHRzLmJ1dHRvblNpemUsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGJ1dHRvbkJvcmRlclJhZGl1czoge1xuXHRcdFx0XHRcdHR5cGU6ICdzdHJpbmcnLFxuXHRcdFx0XHRcdGRlZmF1bHQ6IGRlZmF1bHRzLmJ1dHRvbkJvcmRlclJhZGl1cyxcblx0XHRcdFx0fSxcblx0XHRcdFx0YnV0dG9uQmFja2dyb3VuZENvbG9yOiB7XG5cdFx0XHRcdFx0dHlwZTogJ3N0cmluZycsXG5cdFx0XHRcdFx0ZGVmYXVsdDogZGVmYXVsdHMuYnV0dG9uQmFja2dyb3VuZENvbG9yLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRidXR0b25UZXh0Q29sb3I6IHtcblx0XHRcdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHRcdFx0XHRkZWZhdWx0OiBkZWZhdWx0cy5idXR0b25UZXh0Q29sb3IsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGNvcHlQYXN0ZVZhbHVlOiB7XG5cdFx0XHRcdFx0dHlwZTogJ3N0cmluZycsXG5cdFx0XHRcdFx0ZGVmYXVsdDogZGVmYXVsdHMuY29weVBhc3RlVmFsdWUsXG5cdFx0XHRcdH0sXG5cdFx0XHR9O1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBHZXQgZm9ybSBzZWxlY3RvciBvcHRpb25zLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7QXJyYXl9IEZvcm0gb3B0aW9ucy5cblx0XHQgKi9cblx0XHRnZXRGb3JtT3B0aW9uczogZnVuY3Rpb24oKSB7XG5cblx0XHRcdGNvbnN0IGZvcm1PcHRpb25zID0gd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5mb3Jtcy5tYXAoIHZhbHVlID0+IChcblx0XHRcdFx0eyB2YWx1ZTogdmFsdWUuSUQsIGxhYmVsOiB2YWx1ZS5wb3N0X3RpdGxlIH1cblx0XHRcdCkgKTtcblxuXHRcdFx0Zm9ybU9wdGlvbnMudW5zaGlmdCggeyB2YWx1ZTogJycsIGxhYmVsOiBzdHJpbmdzLmZvcm1fc2VsZWN0IH0gKTtcblxuXHRcdFx0cmV0dXJuIGZvcm1PcHRpb25zO1xuXHRcdH0sXG5cblx0XHQvKipcblx0XHQgKiBHZXQgc2l6ZSBzZWxlY3RvciBvcHRpb25zLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcmV0dXJucyB7QXJyYXl9IFNpemUgb3B0aW9ucy5cblx0XHQgKi9cblx0XHRnZXRTaXplT3B0aW9uczogZnVuY3Rpb24oKSB7XG5cblx0XHRcdHJldHVybiBbXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRsYWJlbDogc3RyaW5ncy5zbWFsbCxcblx0XHRcdFx0XHR2YWx1ZTogJ3NtYWxsJyxcblx0XHRcdFx0fSxcblx0XHRcdFx0e1xuXHRcdFx0XHRcdGxhYmVsOiBzdHJpbmdzLm1lZGl1bSxcblx0XHRcdFx0XHR2YWx1ZTogJ21lZGl1bScsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRsYWJlbDogc3RyaW5ncy5sYXJnZSxcblx0XHRcdFx0XHR2YWx1ZTogJ2xhcmdlJyxcblx0XHRcdFx0fSxcblx0XHRcdF07XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEV2ZW50IGB3cGZvcm1zRm9ybVNlbGVjdG9yRWRpdGAgaGFuZGxlci5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtvYmplY3R9IGUgICAgIEV2ZW50IG9iamVjdC5cblx0XHQgKiBAcGFyYW0ge29iamVjdH0gcHJvcHMgQmxvY2sgcHJvcGVydGllcy5cblx0XHQgKi9cblx0XHRibG9ja0VkaXQ6IGZ1bmN0aW9uKCBlLCBwcm9wcyApIHtcblxuXHRcdFx0Y29uc3QgYmxvY2sgPSBhcHAuZ2V0QmxvY2tDb250YWluZXIoIHByb3BzICk7XG5cblx0XHRcdGlmICggISBibG9jayB8fCAhIGJsb2NrLmRhdGFzZXQgKSB7XG5cdFx0XHRcdHJldHVybjtcblx0XHRcdH1cblxuXHRcdFx0YXBwLmluaXRMZWFkRm9ybVNldHRpbmdzKCBibG9jay5wYXJlbnRFbGVtZW50ICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEluaXQgTGVhZCBGb3JtIFNldHRpbmdzIHBhbmVscy5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtFbGVtZW50fSBibG9jayBCbG9jayBlbGVtZW50LlxuXHRcdCAqL1xuXHRcdGluaXRMZWFkRm9ybVNldHRpbmdzOiBmdW5jdGlvbiggYmxvY2sgKSB7XG5cblx0XHRcdGlmICggISBibG9jayB8fCAhIGJsb2NrLmRhdGFzZXQgKSB7XG5cdFx0XHRcdHJldHVybjtcblx0XHRcdH1cblxuXHRcdFx0aWYgKCAhIGFwcC5pc0Z1bGxTdHlsaW5nRW5hYmxlZCgpICkge1xuXHRcdFx0XHRyZXR1cm47XG5cdFx0XHR9XG5cblx0XHRcdGNvbnN0IGNsaWVudElkID0gYmxvY2suZGF0YXNldC5ibG9jaztcblx0XHRcdGNvbnN0ICRmb3JtID0gJCggYmxvY2sucXVlcnlTZWxlY3RvciggJy53cGZvcm1zLWNvbnRhaW5lcicgKSApO1xuXHRcdFx0Y29uc3QgJHBhbmVsID0gJCggYC53cGZvcm1zLWJsb2NrLXNldHRpbmdzLSR7Y2xpZW50SWR9YCApO1xuXG5cdFx0XHRpZiAoICRmb3JtLmhhc0NsYXNzKCAnd3Bmb3Jtcy1sZWFkLWZvcm1zLWNvbnRhaW5lcicgKSApIHtcblxuXHRcdFx0XHQkcGFuZWxcblx0XHRcdFx0XHQuYWRkQ2xhc3MoICdkaXNhYmxlZF9wYW5lbCcgKVxuXHRcdFx0XHRcdC5maW5kKCAnLndwZm9ybXMtZ3V0ZW5iZXJnLXBhbmVsLW5vdGljZS53cGZvcm1zLWxlYWQtZm9ybS1ub3RpY2UnIClcblx0XHRcdFx0XHQuY3NzKCAnZGlzcGxheScsICdibG9jaycgKTtcblxuXHRcdFx0XHQkcGFuZWxcblx0XHRcdFx0XHQuZmluZCggJy53cGZvcm1zLWd1dGVuYmVyZy1wYW5lbC1ub3RpY2Uud3Bmb3Jtcy11c2UtbW9kZXJuLW5vdGljZScgKVxuXHRcdFx0XHRcdC5jc3MoICdkaXNwbGF5JywgJ25vbmUnICk7XG5cblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHQkcGFuZWxcblx0XHRcdFx0LnJlbW92ZUNsYXNzKCAnZGlzYWJsZWRfcGFuZWwnIClcblx0XHRcdFx0LmZpbmQoICcud3Bmb3Jtcy1ndXRlbmJlcmctcGFuZWwtbm90aWNlLndwZm9ybXMtbGVhZC1mb3JtLW5vdGljZScgKVxuXHRcdFx0XHQuY3NzKCAnZGlzcGxheScsICdub25lJyApO1xuXG5cdFx0XHQkcGFuZWxcblx0XHRcdFx0LmZpbmQoICcud3Bmb3Jtcy1ndXRlbmJlcmctcGFuZWwtbm90aWNlLndwZm9ybXMtdXNlLW1vZGVybi1ub3RpY2UnIClcblx0XHRcdFx0LmNzcyggJ2Rpc3BsYXknLCBudWxsICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEV2ZW50IGB3cGZvcm1zRm9ybVNlbGVjdG9yRm9ybUxvYWRlZGAgaGFuZGxlci5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtvYmplY3R9IGUgRXZlbnQgb2JqZWN0LlxuXHRcdCAqL1xuXHRcdGZvcm1Mb2FkZWQ6IGZ1bmN0aW9uKCBlICkge1xuXG5cdFx0XHRhcHAuaW5pdExlYWRGb3JtU2V0dGluZ3MoIGUuZGV0YWlsLmJsb2NrICk7XG5cdFx0XHRhcHAudXBkYXRlQWNjZW50Q29sb3JzKCBlLmRldGFpbCApO1xuXHRcdFx0YXBwLmxvYWRDaG9pY2VzSlMoIGUuZGV0YWlsICk7XG5cdFx0XHRhcHAuaW5pdFJpY2hUZXh0RmllbGQoIGUuZGV0YWlsLmZvcm1JZCApO1xuXG5cdFx0XHQkKCBlLmRldGFpbC5ibG9jayApXG5cdFx0XHRcdC5vZmYoICdjbGljaycgKVxuXHRcdFx0XHQub24oICdjbGljaycsIGFwcC5ibG9ja0NsaWNrICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIENsaWNrIG9uIHRoZSBibG9jayBldmVudCBoYW5kbGVyLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcGFyYW0ge29iamVjdH0gZSBFdmVudCBvYmplY3QuXG5cdFx0ICovXG5cdFx0YmxvY2tDbGljazogZnVuY3Rpb24oIGUgKSB7XG5cblx0XHRcdGFwcC5pbml0TGVhZEZvcm1TZXR0aW5ncyggZS5jdXJyZW50VGFyZ2V0ICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIFVwZGF0ZSBhY2NlbnQgY29sb3JzIG9mIHNvbWUgZmllbGRzIGluIEdCIGJsb2NrIGluIE1vZGVybiBNYXJrdXAgbW9kZS5cblx0XHQgKlxuXHRcdCAqIEBzaW5jZSAxLjguMVxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtvYmplY3R9IGRldGFpbCBFdmVudCBkZXRhaWxzIG9iamVjdC5cblx0XHQgKi9cblx0XHR1cGRhdGVBY2NlbnRDb2xvcnM6IGZ1bmN0aW9uKCBkZXRhaWwgKSB7XG5cblx0XHRcdGlmIChcblx0XHRcdFx0ISB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLmlzX21vZGVybl9tYXJrdXAgfHxcblx0XHRcdFx0ISB3aW5kb3cuV1BGb3JtcyB8fFxuXHRcdFx0XHQhIHdpbmRvdy5XUEZvcm1zLkZyb250ZW5kTW9kZXJuIHx8XG5cdFx0XHRcdCEgZGV0YWlsLmJsb2NrXG5cdFx0XHQpIHtcblx0XHRcdFx0cmV0dXJuO1xuXHRcdFx0fVxuXG5cdFx0XHRjb25zdCAkZm9ybSA9ICQoIGRldGFpbC5ibG9jay5xdWVyeVNlbGVjdG9yKCBgI3dwZm9ybXMtJHtkZXRhaWwuZm9ybUlkfWAgKSApLFxuXHRcdFx0XHRGcm9udGVuZE1vZGVybiA9IHdpbmRvdy5XUEZvcm1zLkZyb250ZW5kTW9kZXJuO1xuXG5cdFx0XHRGcm9udGVuZE1vZGVybi51cGRhdGVHQkJsb2NrUGFnZUluZGljYXRvckNvbG9yKCAkZm9ybSApO1xuXHRcdFx0RnJvbnRlbmRNb2Rlcm4udXBkYXRlR0JCbG9ja0ljb25DaG9pY2VzQ29sb3IoICRmb3JtICk7XG5cdFx0XHRGcm9udGVuZE1vZGVybi51cGRhdGVHQkJsb2NrUmF0aW5nQ29sb3IoICRmb3JtICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEluaXQgTW9kZXJuIHN0eWxlIERyb3Bkb3duIGZpZWxkcyAoPHNlbGVjdD4pLlxuXHRcdCAqXG5cdFx0ICogQHNpbmNlIDEuOC4xXG5cdFx0ICpcblx0XHQgKiBAcGFyYW0ge29iamVjdH0gZGV0YWlsIEV2ZW50IGRldGFpbHMgb2JqZWN0LlxuXHRcdCAqL1xuXHRcdGxvYWRDaG9pY2VzSlM6IGZ1bmN0aW9uKCBkZXRhaWwgKSB7XG5cblx0XHRcdGlmICggdHlwZW9mIHdpbmRvdy5DaG9pY2VzICE9PSAnZnVuY3Rpb24nICkge1xuXHRcdFx0XHRyZXR1cm47XG5cdFx0XHR9XG5cblx0XHRcdGNvbnN0ICRmb3JtID0gJCggZGV0YWlsLmJsb2NrLnF1ZXJ5U2VsZWN0b3IoIGAjd3Bmb3Jtcy0ke2RldGFpbC5mb3JtSWR9YCApICk7XG5cblx0XHRcdCRmb3JtLmZpbmQoICcuY2hvaWNlc2pzLXNlbGVjdCcgKS5lYWNoKCBmdW5jdGlvbiggaWR4LCBlbCApIHtcblxuXHRcdFx0XHRjb25zdCAkZWwgPSAkKCBlbCApO1xuXG5cdFx0XHRcdGlmICggJGVsLmRhdGEoICdjaG9pY2UnICkgPT09ICdhY3RpdmUnICkge1xuXHRcdFx0XHRcdHJldHVybjtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHZhciBhcmdzID0gd2luZG93LndwZm9ybXNfY2hvaWNlc2pzX2NvbmZpZyB8fCB7fSxcblx0XHRcdFx0XHRzZWFyY2hFbmFibGVkID0gJGVsLmRhdGEoICdzZWFyY2gtZW5hYmxlZCcgKSxcblx0XHRcdFx0XHQkZmllbGQgPSAkZWwuY2xvc2VzdCggJy53cGZvcm1zLWZpZWxkJyApO1xuXG5cdFx0XHRcdGFyZ3Muc2VhcmNoRW5hYmxlZCA9ICd1bmRlZmluZWQnICE9PSB0eXBlb2Ygc2VhcmNoRW5hYmxlZCA/IHNlYXJjaEVuYWJsZWQgOiB0cnVlO1xuXHRcdFx0XHRhcmdzLmNhbGxiYWNrT25Jbml0ID0gZnVuY3Rpb24oKSB7XG5cblx0XHRcdFx0XHR2YXIgc2VsZiA9IHRoaXMsXG5cdFx0XHRcdFx0XHQkZWxlbWVudCA9ICQoIHNlbGYucGFzc2VkRWxlbWVudC5lbGVtZW50ICksXG5cdFx0XHRcdFx0XHQkaW5wdXQgPSAkKCBzZWxmLmlucHV0LmVsZW1lbnQgKSxcblx0XHRcdFx0XHRcdHNpemVDbGFzcyA9ICRlbGVtZW50LmRhdGEoICdzaXplLWNsYXNzJyApO1xuXG5cdFx0XHRcdFx0Ly8gQWRkIENTUy1jbGFzcyBmb3Igc2l6ZS5cblx0XHRcdFx0XHRpZiAoIHNpemVDbGFzcyApIHtcblx0XHRcdFx0XHRcdCQoIHNlbGYuY29udGFpbmVyT3V0ZXIuZWxlbWVudCApLmFkZENsYXNzKCBzaXplQ2xhc3MgKTtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHQvKipcblx0XHRcdFx0XHQgKiBJZiBhIG11bHRpcGxlIHNlbGVjdCBoYXMgc2VsZWN0ZWQgY2hvaWNlcyAtIGhpZGUgYSBwbGFjZWhvbGRlciB0ZXh0LlxuXHRcdFx0XHRcdCAqIEluIGNhc2UgaWYgc2VsZWN0IGlzIGVtcHR5IC0gd2UgcmV0dXJuIHBsYWNlaG9sZGVyIHRleHQgYmFjay5cblx0XHRcdFx0XHQgKi9cblx0XHRcdFx0XHRpZiAoICRlbGVtZW50LnByb3AoICdtdWx0aXBsZScgKSApIHtcblxuXHRcdFx0XHRcdFx0Ly8gT24gaW5pdCBldmVudC5cblx0XHRcdFx0XHRcdCRpbnB1dC5kYXRhKCAncGxhY2Vob2xkZXInLCAkaW5wdXQuYXR0ciggJ3BsYWNlaG9sZGVyJyApICk7XG5cblx0XHRcdFx0XHRcdGlmICggc2VsZi5nZXRWYWx1ZSggdHJ1ZSApLmxlbmd0aCApIHtcblx0XHRcdFx0XHRcdFx0JGlucHV0LnJlbW92ZUF0dHIoICdwbGFjZWhvbGRlcicgKTtcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHR0aGlzLmRpc2FibGUoKTtcblx0XHRcdFx0XHQkZmllbGQuZmluZCggJy5pcy1kaXNhYmxlZCcgKS5yZW1vdmVDbGFzcyggJ2lzLWRpc2FibGVkJyApO1xuXHRcdFx0XHR9O1xuXG5cdFx0XHRcdHRyeSB7XG5cdFx0XHRcdFx0Y29uc3QgY2hvaWNlc0luc3RhbmNlID0gIG5ldyBDaG9pY2VzKCBlbCwgYXJncyApO1xuXG5cdFx0XHRcdFx0Ly8gU2F2ZSBDaG9pY2VzLmpzIGluc3RhbmNlIGZvciBmdXR1cmUgYWNjZXNzLlxuXHRcdFx0XHRcdCRlbC5kYXRhKCAnY2hvaWNlc2pzJywgY2hvaWNlc0luc3RhbmNlICk7XG5cblx0XHRcdFx0fSBjYXRjaCAoIGUgKSB7fSAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG5vLWVtcHR5XG5cdFx0XHR9ICk7XG5cdFx0fSxcblxuXHRcdC8qKlxuXHRcdCAqIEluaXRpYWxpemUgUmljaFRleHQgZmllbGQuXG5cdFx0ICpcblx0XHQgKiBAc2luY2UgMS44LjFcblx0XHQgKlxuXHRcdCAqIEBwYXJhbSB7aW50fSBmb3JtSWQgRm9ybSBJRC5cblx0XHQgKi9cblx0XHRpbml0UmljaFRleHRGaWVsZDogZnVuY3Rpb24oIGZvcm1JZCApIHtcblxuXHRcdFx0Ly8gU2V0IGRlZmF1bHQgdGFiIHRvIGBWaXN1YWxgLlxuXHRcdFx0JCggYCN3cGZvcm1zLSR7Zm9ybUlkfSAud3AtZWRpdG9yLXdyYXBgICkucmVtb3ZlQ2xhc3MoICdodG1sLWFjdGl2ZScgKS5hZGRDbGFzcyggJ3RtY2UtYWN0aXZlJyApO1xuXHRcdH0sXG5cdH07XG5cblx0Ly8gUHJvdmlkZSBhY2Nlc3MgdG8gcHVibGljIGZ1bmN0aW9ucy9wcm9wZXJ0aWVzLlxuXHRyZXR1cm4gYXBwO1xuXG59KCBkb2N1bWVudCwgd2luZG93LCBqUXVlcnkgKSApO1xuXG4vLyBJbml0aWFsaXplLlxuV1BGb3Jtcy5Gb3JtU2VsZWN0b3IuaW5pdCgpO1xuIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBOztBQUVBLFlBQVk7O0FBRVo7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUpBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUtBLElBQUlBLE9BQU8sR0FBR0MsTUFBTSxDQUFDRCxPQUFPLElBQUksQ0FBQyxDQUFDO0FBRWxDQSxPQUFPLENBQUNFLFlBQVksR0FBR0YsT0FBTyxDQUFDRSxZQUFZLElBQU0sVUFBVUMsUUFBUSxFQUFFRixNQUFNLEVBQUVHLENBQUMsRUFBRztFQUVoRixVQUFnRkMsRUFBRTtJQUFBLDJCQUExRUMsZ0JBQWdCO0lBQUVDLGdCQUFnQixxQ0FBR0YsRUFBRSxDQUFDRyxVQUFVLENBQUNELGdCQUFnQjtFQUMzRSxrQkFBOENGLEVBQUUsQ0FBQ0ksT0FBTztJQUFoREMsYUFBYSxlQUFiQSxhQUFhO0lBQUVDLFFBQVEsZUFBUkEsUUFBUTtJQUFFQyxRQUFRLGVBQVJBLFFBQVE7RUFDekMsSUFBUUMsaUJBQWlCLEdBQUtSLEVBQUUsQ0FBQ1MsTUFBTSxD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
},{}]},{},[1])