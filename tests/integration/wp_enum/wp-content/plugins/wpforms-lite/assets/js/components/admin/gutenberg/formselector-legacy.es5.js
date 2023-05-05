(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/* global wpforms_gutenberg_form_selector */
/* jshint es3: false, esversion: 6 */

'use strict';

var _wp = wp,
  _wp$serverSideRender = _wp.serverSideRender,
  ServerSideRender = _wp$serverSideRender === void 0 ? wp.components.ServerSideRender : _wp$serverSideRender;
var _wp$element = wp.element,
  createElement = _wp$element.createElement,
  Fragment = _wp$element.Fragment;
var registerBlockType = wp.blocks.registerBlockType;
var _ref = wp.blockEditor || wp.editor,
  InspectorControls = _ref.InspectorControls;
var _wp$components = wp.components,
  SelectControl = _wp$components.SelectControl,
  ToggleControl = _wp$components.ToggleControl,
  PanelBody = _wp$components.PanelBody,
  Placeholder = _wp$components.Placeholder;
var wpformsIcon = createElement('svg', {
  width: 20,
  height: 20,
  viewBox: '0 0 612 612',
  className: 'dashicon'
}, createElement('path', {
  fill: 'currentColor',
  d: 'M544,0H68C30.445,0,0,30.445,0,68v476c0,37.556,30.445,68,68,68h476c37.556,0,68-30.444,68-68V68 C612,30.445,581.556,0,544,0z M464.44,68L387.6,120.02L323.34,68H464.44z M288.66,68l-64.26,52.02L147.56,68H288.66z M544,544H68 V68h22.1l136,92.14l79.9-64.6l79.56,64.6l136-92.14H544V544z M114.24,263.16h95.88v-48.28h-95.88V263.16z M114.24,360.4h95.88 v-48.62h-95.88V360.4z M242.76,360.4h255v-48.62h-255V360.4L242.76,360.4z M242.76,263.16h255v-48.28h-255V263.16L242.76,263.16z M368.22,457.3h129.54V408H368.22V457.3z'
}));
registerBlockType('wpforms/form-selector', {
  title: wpforms_gutenberg_form_selector.strings.title,
  description: wpforms_gutenberg_form_selector.strings.description,
  icon: wpformsIcon,
  keywords: wpforms_gutenberg_form_selector.strings.form_keywords,
  category: 'widgets',
  attributes: {
    formId: {
      type: 'string'
    },
    displayTitle: {
      type: 'boolean'
    },
    displayDesc: {
      type: 'boolean'
    },
    preview: {
      type: 'boolean'
    }
  },
  example: {
    attributes: {
      preview: true
    }
  },
  edit: function edit(props) {
    // eslint-disable-line max-lines-per-function
    var _props$attributes = props.attributes,
      _props$attributes$for = _props$attributes.formId,
      formId = _props$attributes$for === void 0 ? '' : _props$attributes$for,
      _props$attributes$dis = _props$attributes.displayTitle,
      displayTitle = _props$attributes$dis === void 0 ? false : _props$attributes$dis,
      _props$attributes$dis2 = _props$attributes.displayDesc,
      displayDesc = _props$attributes$dis2 === void 0 ? false : _props$attributes$dis2,
      _props$attributes$pre = _props$attributes.preview,
      preview = _props$attributes$pre === void 0 ? false : _props$attributes$pre,
      setAttributes = props.setAttributes;
    var formOptions = wpforms_gutenberg_form_selector.forms.map(function (value) {
      return {
        value: value.ID,
        label: value.post_title
      };
    });
    var strings = wpforms_gutenberg_form_selector.strings;
    var jsx;
    formOptions.unshift({
      value: '',
      label: wpforms_gutenberg_form_selector.strings.form_select
    });
    function selectForm(value) {
      // eslint-disable-line jsdoc/require-jsdoc
      setAttributes({
        formId: value
      });
    }
    function toggleDisplayTitle(value) {
      // eslint-disable-line jsdoc/require-jsdoc
      setAttributes({
        displayTitle: value
      });
    }
    function toggleDisplayDesc(value) {
      // eslint-disable-line jsdoc/require-jsdoc
      setAttributes({
        displayDesc: value
      });
    }
    jsx = [/*#__PURE__*/React.createElement(InspectorControls, {
      key: "wpforms-gutenberg-form-selector-inspector-controls"
    }, /*#__PURE__*/React.createElement(PanelBody, {
      title: wpforms_gutenberg_form_selector.strings.form_settings
    }, /*#__PURE__*/React.createElement(SelectControl, {
      label: wpforms_gutenberg_form_selector.strings.form_selected,
      value: formId,
      options: formOptions,
      onChange: selectForm
    }), /*#__PURE__*/React.createElement(ToggleControl, {
      label: wpforms_gutenberg_form_selector.strings.show_title,
      checked: displayTitle,
      onChange: toggleDisplayTitle
    }), /*#__PURE__*/React.createElement(ToggleControl, {
      label: wpforms_gutenberg_form_selector.strings.show_description,
      checked: displayDesc,
      onChange: toggleDisplayDesc
    }), /*#__PURE__*/React.createElement("p", {
      className: "wpforms-gutenberg-panel-notice"
    }, /*#__PURE__*/React.createElement("strong", null, strings.update_wp_notice_head), strings.update_wp_notice_text, " ", /*#__PURE__*/React.createElement("a", {
      href: strings.update_wp_notice_link,
      rel: "noreferrer",
      target: "_blank"
    }, strings.learn_more))))];
    if (formId) {
      jsx.push( /*#__PURE__*/React.createElement(ServerSideRender, {
        key: "wpforms-gutenberg-form-selector-server-side-renderer",
        block: "wpforms/form-selector",
        attributes: props.attributes
      }));
    } else if (preview) {
      jsx.push( /*#__PURE__*/React.createElement(Fragment, {
        key: "wpforms-gutenberg-form-selector-fragment-block-preview"
      }, /*#__PURE__*/React.createElement("img", {
        src: wpforms_gutenberg_form_selector.block_preview_url,
        style: {
          width: '100%'
        }
      })));
    } else {
      jsx.push( /*#__PURE__*/React.createElement(Placeholder, {
        key: "wpforms-gutenberg-form-selector-wrap",
        className: "wpforms-gutenberg-form-selector-wrap"
      }, /*#__PURE__*/React.createElement("img", {
        src: wpforms_gutenberg_form_selector.logo_url
      }), /*#__PURE__*/React.createElement("h3", null, wpforms_gutenberg_form_selector.strings.title), /*#__PURE__*/React.createElement(SelectControl, {
        key: "wpforms-gutenberg-form-selector-select-control",
        value: formId,
        options: formOptions,
        onChange: selectForm
      })));
    }
    return jsx;
  },
  save: function save() {
    return null;
  }
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJ3cCIsInNlcnZlclNpZGVSZW5kZXIiLCJTZXJ2ZXJTaWRlUmVuZGVyIiwiY29tcG9uZW50cyIsImVsZW1lbnQiLCJjcmVhdGVFbGVtZW50IiwiRnJhZ21lbnQiLCJyZWdpc3RlckJsb2NrVHlwZSIsImJsb2NrcyIsImJsb2NrRWRpdG9yIiwiZWRpdG9yIiwiSW5zcGVjdG9yQ29udHJvbHMiLCJTZWxlY3RDb250cm9sIiwiVG9nZ2xlQ29udHJvbCIsIlBhbmVsQm9keSIsIlBsYWNlaG9sZGVyIiwid3Bmb3Jtc0ljb24iLCJ3aWR0aCIsImhlaWdodCIsInZpZXdCb3giLCJjbGFzc05hbWUiLCJmaWxsIiwiZCIsInRpdGxlIiwid3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3RvciIsInN0cmluZ3MiLCJkZXNjcmlwdGlvbiIsImljb24iLCJrZXl3b3JkcyIsImZvcm1fa2V5d29yZHMiLCJjYXRlZ29yeSIsImF0dHJpYnV0ZXMiLCJmb3JtSWQiLCJ0eXBlIiwiZGlzcGxheVRpdGxlIiwiZGlzcGxheURlc2MiLCJwcmV2aWV3IiwiZXhhbXBsZSIsImVkaXQiLCJwcm9wcyIsInNldEF0dHJpYnV0ZXMiLCJmb3JtT3B0aW9ucyIsImZvcm1zIiwibWFwIiwidmFsdWUiLCJJRCIsImxhYmVsIiwicG9zdF90aXRsZSIsImpzeCIsInVuc2hpZnQiLCJmb3JtX3NlbGVjdCIsInNlbGVjdEZvcm0iLCJ0b2dnbGVEaXNwbGF5VGl0bGUiLCJ0b2dnbGVEaXNwbGF5RGVzYyIsImZvcm1fc2V0dGluZ3MiLCJmb3JtX3NlbGVjdGVkIiwic2hvd190aXRsZSIsInNob3dfZGVzY3JpcHRpb24iLCJ1cGRhdGVfd3Bfbm90aWNlX2hlYWQiLCJ1cGRhdGVfd3Bfbm90aWNlX3RleHQiLCJ1cGRhdGVfd3Bfbm90aWNlX2xpbmsiLCJsZWFybl9tb3JlIiwicHVzaCIsImJsb2NrX3ByZXZpZXdfdXJsIiwibG9nb191cmwiLCJzYXZlIl0sInNvdXJjZXMiOlsiZmFrZV9iMDQ5ZWNkYy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKiBnbG9iYWwgd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3RvciAqL1xuLyoganNoaW50IGVzMzogZmFsc2UsIGVzdmVyc2lvbjogNiAqL1xuXG4ndXNlIHN0cmljdCc7XG5cbmNvbnN0IHsgc2VydmVyU2lkZVJlbmRlcjogU2VydmVyU2lkZVJlbmRlciA9IHdwLmNvbXBvbmVudHMuU2VydmVyU2lkZVJlbmRlciB9ID0gd3A7XG5jb25zdCB7IGNyZWF0ZUVsZW1lbnQsIEZyYWdtZW50IH0gPSB3cC5lbGVtZW50O1xuY29uc3QgeyByZWdpc3RlckJsb2NrVHlwZSB9ID0gd3AuYmxvY2tzO1xuY29uc3QgeyBJbnNwZWN0b3JDb250cm9scyB9ID0gd3AuYmxvY2tFZGl0b3IgfHwgd3AuZWRpdG9yO1xuY29uc3QgeyBTZWxlY3RDb250cm9sLCBUb2dnbGVDb250cm9sLCBQYW5lbEJvZHksIFBsYWNlaG9sZGVyIH0gPSB3cC5jb21wb25lbnRzO1xuXG5jb25zdCB3cGZvcm1zSWNvbiA9IGNyZWF0ZUVsZW1lbnQoICdzdmcnLCB7IHdpZHRoOiAyMCwgaGVpZ2h0OiAyMCwgdmlld0JveDogJzAgMCA2MTIgNjEyJywgY2xhc3NOYW1lOiAnZGFzaGljb24nIH0sXG5cdGNyZWF0ZUVsZW1lbnQoICdwYXRoJywge1xuXHRcdGZpbGw6ICdjdXJyZW50Q29sb3InLFxuXHRcdGQ6ICdNNTQ0LDBINjhDMzAuNDQ1LDAsMCwzMC40NDUsMCw2OHY0NzZjMCwzNy41NTYsMzAuNDQ1LDY4LDY4LDY4aDQ3NmMzNy41NTYsMCw2OC0zMC40NDQsNjgtNjhWNjggQzYxMiwzMC40NDUsNTgxLjU1NiwwLDU0NCwweiBNNDY0LjQ0LDY4TDM4Ny42LDEyMC4wMkwzMjMuMzQsNjhINDY0LjQ0eiBNMjg4LjY2LDY4bC02NC4yNiw1Mi4wMkwxNDcuNTYsNjhIMjg4LjY2eiBNNTQ0LDU0NEg2OCBWNjhoMjIuMWwxMzYsOTIuMTRsNzkuOS02NC42bDc5LjU2LDY0LjZsMTM2LTkyLjE0SDU0NFY1NDR6IE0xMTQuMjQsMjYzLjE2aDk1Ljg4di00OC4yOGgtOTUuODhWMjYzLjE2eiBNMTE0LjI0LDM2MC40aDk1Ljg4IHYtNDguNjJoLTk1Ljg4VjM2MC40eiBNMjQyLjc2LDM2MC40aDI1NXYtNDguNjJoLTI1NVYzNjAuNEwyNDIuNzYsMzYwLjR6IE0yNDIuNzYsMjYzLjE2aDI1NXYtNDguMjhoLTI1NVYyNjMuMTZMMjQyLjc2LDI2My4xNnogTTM2OC4yMiw0NTcuM2gxMjkuNTRWNDA4SDM2OC4yMlY0NTcuM3onLFxuXHR9IClcbik7XG5cbnJlZ2lzdGVyQmxvY2tUeXBlKCAnd3Bmb3Jtcy9mb3JtLXNlbGVjdG9yJywge1xuXHR0aXRsZTogd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5zdHJpbmdzLnRpdGxlLFxuXHRkZXNjcmlwdGlvbjogd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5zdHJpbmdzLmRlc2NyaXB0aW9uLFxuXHRpY29uOiB3cGZvcm1zSWNvbixcblx0a2V5d29yZHM6IHdwZm9ybXNfZ3V0ZW5iZXJnX2Zvcm1fc2VsZWN0b3Iuc3RyaW5ncy5mb3JtX2tleXdvcmRzLFxuXHRjYXRlZ29yeTogJ3dpZGdldHMnLFxuXHRhdHRyaWJ1dGVzOiB7XG5cdFx0Zm9ybUlkOiB7XG5cdFx0XHR0eXBlOiAnc3RyaW5nJyxcblx0XHR9LFxuXHRcdGRpc3BsYXlUaXRsZToge1xuXHRcdFx0dHlwZTogJ2Jvb2xlYW4nLFxuXHRcdH0sXG5cdFx0ZGlzcGxheURlc2M6IHtcblx0XHRcdHR5cGU6ICdib29sZWFuJyxcblx0XHR9LFxuXHRcdHByZXZpZXc6IHtcblx0XHRcdHR5cGU6ICdib29sZWFuJyxcblx0XHR9LFxuXHR9LFxuXHRleGFtcGxlOiB7XG5cdFx0YXR0cmlidXRlczoge1xuXHRcdFx0cHJldmlldzogdHJ1ZSxcblx0XHR9LFxuXHR9LFxuXHRlZGl0KCBwcm9wcyApIHsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBtYXgtbGluZXMtcGVyLWZ1bmN0aW9uXG5cdFx0Y29uc3QgeyBhdHRyaWJ1dGVzOiB7IGZvcm1JZCA9ICcnLCBkaXNwbGF5VGl0bGUgPSBmYWxzZSwgZGlzcGxheURlc2MgPSBmYWxzZSwgcHJldmlldyA9IGZhbHNlIH0sIHNldEF0dHJpYnV0ZXMgfSA9IHByb3BzO1xuXHRcdGNvbnN0IGZvcm1PcHRpb25zID0gd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5mb3Jtcy5tYXAoIHZhbHVlID0+IChcblx0XHRcdHsgdmFsdWU6IHZhbHVlLklELCBsYWJlbDogdmFsdWUucG9zdF90aXRsZSB9XG5cdFx0KSApO1xuXHRcdGNvbnN0IHN0cmluZ3MgPSB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLnN0cmluZ3M7XG5cdFx0bGV0IGpzeDtcblxuXHRcdGZvcm1PcHRpb25zLnVuc2hpZnQoIHsgdmFsdWU6ICcnLCBsYWJlbDogd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5zdHJpbmdzLmZvcm1fc2VsZWN0IH0gKTtcblxuXHRcdGZ1bmN0aW9uIHNlbGVjdEZvcm0oIHZhbHVlICkgeyAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGpzZG9jL3JlcXVpcmUtanNkb2Ncblx0XHRcdHNldEF0dHJpYnV0ZXMoIHsgZm9ybUlkOiB2YWx1ZSB9ICk7XG5cdFx0fVxuXG5cdFx0ZnVuY3Rpb24gdG9nZ2xlRGlzcGxheVRpdGxlKCB2YWx1ZSApIHsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBqc2RvYy9yZXF1aXJlLWpzZG9jXG5cdFx0XHRzZXRBdHRyaWJ1dGVzKCB7IGRpc3BsYXlUaXRsZTogdmFsdWUgfSApO1xuXHRcdH1cblxuXHRcdGZ1bmN0aW9uIHRvZ2dsZURpc3BsYXlEZXNjKCB2YWx1ZSApIHsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBqc2RvYy9yZXF1aXJlLWpzZG9jXG5cdFx0XHRzZXRBdHRyaWJ1dGVzKCB7IGRpc3BsYXlEZXNjOiB2YWx1ZSB9ICk7XG5cdFx0fVxuXG5cdFx0anN4ID0gW1xuXHRcdFx0PEluc3BlY3RvckNvbnRyb2xzIGtleT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3ItaW5zcGVjdG9yLWNvbnRyb2xzXCI+XG5cdFx0XHRcdDxQYW5lbEJvZHkgdGl0bGU9eyB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLnN0cmluZ3MuZm9ybV9zZXR0aW5ncyB9PlxuXHRcdFx0XHRcdDxTZWxlY3RDb250cm9sXG5cdFx0XHRcdFx0XHRsYWJlbD17IHdwZm9ybXNfZ3V0ZW5iZXJnX2Zvcm1fc2VsZWN0b3Iuc3RyaW5ncy5mb3JtX3NlbGVjdGVkIH1cblx0XHRcdFx0XHRcdHZhbHVlPXsgZm9ybUlkIH1cblx0XHRcdFx0XHRcdG9wdGlvbnM9eyBmb3JtT3B0aW9ucyB9XG5cdFx0XHRcdFx0XHRvbkNoYW5nZT17IHNlbGVjdEZvcm0gfVxuXHRcdFx0XHRcdC8+XG5cdFx0XHRcdFx0PFRvZ2dsZUNvbnRyb2xcblx0XHRcdFx0XHRcdGxhYmVsPXsgd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5zdHJpbmdzLnNob3dfdGl0bGUgfVxuXHRcdFx0XHRcdFx0Y2hlY2tlZD17IGRpc3BsYXlUaXRsZSB9XG5cdFx0XHRcdFx0XHRvbkNoYW5nZT17IHRvZ2dsZURpc3BsYXlUaXRsZSB9XG5cdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHQ8VG9nZ2xlQ29udHJvbFxuXHRcdFx0XHRcdFx0bGFiZWw9eyB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLnN0cmluZ3Muc2hvd19kZXNjcmlwdGlvbiB9XG5cdFx0XHRcdFx0XHRjaGVja2VkPXsgZGlzcGxheURlc2MgfVxuXHRcdFx0XHRcdFx0b25DaGFuZ2U9eyB0b2dnbGVEaXNwbGF5RGVzYyB9XG5cdFx0XHRcdFx0Lz5cblx0XHRcdFx0XHQ8cCBjbGFzc05hbWU9XCJ3cGZvcm1zLWd1dGVuYmVyZy1wYW5lbC1ub3RpY2VcIj5cblx0XHRcdFx0XHRcdDxzdHJvbmc+eyBzdHJpbmdzLnVwZGF0ZV93cF9ub3RpY2VfaGVhZCB9PC9zdHJvbmc+XG5cdFx0XHRcdFx0XHR7IHN0cmluZ3MudXBkYXRlX3dwX25vdGljZV90ZXh0IH0gPGEgaHJlZj17c3RyaW5ncy51cGRhdGVfd3Bfbm90aWNlX2xpbmt9IHJlbD1cIm5vcmVmZXJyZXJcIiB0YXJnZXQ9XCJfYmxhbmtcIj57IHN0cmluZ3MubGVhcm5fbW9yZSB9PC9hPlxuXHRcdFx0XHRcdDwvcD5cblxuXHRcdFx0XHQ8L1BhbmVsQm9keT5cblx0XHRcdDwvSW5zcGVjdG9yQ29udHJvbHM+LFxuXHRcdF07XG5cblx0XHRpZiAoIGZvcm1JZCApIHtcblx0XHRcdGpzeC5wdXNoKFxuXHRcdFx0XHQ8U2VydmVyU2lkZVJlbmRlclxuXHRcdFx0XHRcdGtleT1cIndwZm9ybXMtZ3V0ZW5iZXJnLWZvcm0tc2VsZWN0b3Itc2VydmVyLXNpZGUtcmVuZGVyZXJcIlxuXHRcdFx0XHRcdGJsb2NrPVwid3Bmb3Jtcy9mb3JtLXNlbGVjdG9yXCJcblx0XHRcdFx0XHRhdHRyaWJ1dGVzPXsgcHJvcHMuYXR0cmlidXRlcyB9XG5cdFx0XHRcdC8+XG5cdFx0XHQpO1xuXHRcdH0gZWxzZSBpZiAoIHByZXZpZXcgKSB7XG5cdFx0XHRqc3gucHVzaChcblx0XHRcdFx0PEZyYWdtZW50XG5cdFx0XHRcdFx0a2V5PVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci1mcmFnbWVudC1ibG9jay1wcmV2aWV3XCI+XG5cdFx0XHRcdFx0PGltZyBzcmM9eyB3cGZvcm1zX2d1dGVuYmVyZ19mb3JtX3NlbGVjdG9yLmJsb2NrX3ByZXZpZXdfdXJsIH0gc3R5bGU9e3sgd2lkdGg6ICcxMDAlJyB9fS8+XG5cdFx0XHRcdDwvRnJhZ21lbnQ+XG5cdFx0XHQpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRqc3gucHVzaChcblx0XHRcdFx0PFBsYWNlaG9sZGVyXG5cdFx0XHRcdFx0a2V5PVwid3Bmb3Jtcy1ndXRlbmJlcmctZm9ybS1zZWxlY3Rvci13cmFwXCJcblx0XHRcdFx0XHRjbGFzc05hbWU9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLXdyYXBcIj5cblx0XHRcdFx0XHQ8aW1nIHNyYz17IHdwZm9ybXNfZ3V0ZW5iZXJnX2Zvcm1fc2VsZWN0b3IubG9nb191cmwgfS8+XG5cdFx0XHRcdFx0PGgzPnsgd3Bmb3Jtc19ndXRlbmJlcmdfZm9ybV9zZWxlY3Rvci5zdHJpbmdzLnRpdGxlIH08L2gzPlxuXHRcdFx0XHRcdDxTZWxlY3RDb250cm9sXG5cdFx0XHRcdFx0XHRrZXk9XCJ3cGZvcm1zLWd1dGVuYmVyZy1mb3JtLXNlbGVjdG9yLXNlbGVjdC1jb250cm9sXCJcblx0XHRcdFx0XHRcdHZhbHVlPXsgZm9ybUlkIH1cblx0XHRcdFx0XHRcdG9wdGlvbnM9eyBmb3JtT3B0aW9ucyB9XG5cdFx0XHRcdFx0XHRvbkNoYW5nZT17IHNlbGVjdEZvcm0gfVxuXHRcdFx0XHRcdC8+XG5cdFx0XHRcdDwvUGxhY2Vob2xkZXI+XG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdHJldHVybiBqc3g7XG5cdH0sXG5cdHNhdmUoKSB7XG5cdFx0cmV0dXJuIG51bGw7XG5cdH0sXG59ICk7XG4iXSwibWFwcGluZ3MiOiJBQUFBO0FBQ0E7O0FBRUEsWUFBWTs7QUFFWixVQUFnRkEsRUFBRTtFQUFBLDJCQUExRUMsZ0JBQWdCO0VBQUVDLGdCQUFnQixxQ0FBR0YsRUFBRSxDQUFDRyxVQUFVLENBQUNELGdCQUFnQjtBQUMzRSxrQkFBb0NGLEVBQUUsQ0FBQ0ksT0FBTztFQUF0Q0MsYUFBYSxlQUFiQSxhQUFhO0VBQUVDLFFBQVEsZUFBUkEsUUFBUTtBQUMvQixJQUFRQyxpQkFBaUIsR0FBS1AsRUFBRSxDQUFDUSxNQUFNLENBQS9CRCxpQkFBaUI7QUFDekIsV0FBOEJQLEVBQUUsQ0FBQ1MsV0FBVyxJQUFJVCxFQUFFLENBQUNVLE1BQU07RUFBakRDLGlCQUFpQixRQUFqQkEsaUJBQWlCO0FBQ3pCLHFCQUFpRVgsRUFBRSxDQUFDRyxVQUFVO0VBQXRFUyxhQUFhLGtCQUFiQSxhQUFhO0VBQUVDLGFBQWEsa0JBQWJBLGFBQWE7RUFBRUMsU0FBUyxrQkFBVEEsU0FBUztFQUFFQyxX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
},{}]},{},[1])