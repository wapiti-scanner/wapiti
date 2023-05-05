/* global wpforms_gutenberg_form_selector, Choices */
/* jshint es3: false, esversion: 6 */

'use strict';

/**
 * Gutenberg editor block.
 *
 * @since 1.8.1
 */
var WPForms = window.WPForms || {};

WPForms.FormSelector = WPForms.FormSelector || ( function( document, window, $ ) {

	const { serverSideRender: ServerSideRender = wp.components.ServerSideRender } = wp;
	const { createElement, Fragment, useState } = wp.element;
	const { registerBlockType } = wp.blocks;
	const { InspectorControls, InspectorAdvancedControls, PanelColorSettings } = wp.blockEditor || wp.editor;
	const { SelectControl, ToggleControl, PanelBody, Placeholder, Flex, FlexBlock, __experimentalUnitControl, TextareaControl, Button, Modal } = wp.components;
	const { strings, defaults, sizes } = wpforms_gutenberg_form_selector;
	const defaultStyleSettings = defaults;

	/**
	 * Blocks runtime data.
	 *
	 * @since 1.8.1
	 *
	 * @type {object}
	 */
	let blocks = {};

	/**
	 * Whether it is needed to trigger server rendering.
	 *
	 * @since 1.8.1
	 *
	 * @type {boolean}
	 */
	let triggerServerRender = true;

	/**
	 * Public functions and properties.
	 *
	 * @since 1.8.1
	 *
	 * @type {object}
	 */
	const app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.8.1
		 */
		init: function() {

			app.initDefaults();
			app.registerBlock();

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.8.1
		 */
		ready: function() {

			app.events();
		},

		/**
		 * Events.
		 *
		 * @since 1.8.1
		 */
		events: function() {

			$( window )
				.on( 'wpformsFormSelectorEdit', _.debounce( app.blockEdit, 250 ) )
				.on( 'wpformsFormSelectorFormLoaded', _.debounce( app.formLoaded, 250 ) );
		},

		/**
		 * Register block.
		 *
		 * @since 1.8.1
		 */
		registerBlock: function() {

			registerBlockType( 'wpforms/form-selector', {
				title: strings.title,
				description: strings.description,
				icon: app.getIcon(),
				keywords: strings.form_keywords,
				category: 'widgets',
				attributes: app.getBlockAttributes(),
				example: {
					attributes: {
						preview: true,
					},
				},
				edit: function( props ) {

					const { attributes } = props;
					const formOptions = app.getFormOptions();
					const sizeOptions = app.getSizeOptions();
					const handlers = app.getSettingsFieldsHandlers( props );

					// Store block clientId in attributes.
					props.setAttributes( {
						clientId: props.clientId,
					} );

					// Main block settings.
					let jsx = [
						app.jsxParts.getMainSettings( attributes, handlers, formOptions ),
					];

					// Form style settings & block content.
					if ( attributes.formId ) {
						jsx.push(
							app.jsxParts.getStyleSettings( attributes, handlers, sizeOptions ),
							app.jsxParts.getAdvancedSettings( attributes, handlers ),
							app.jsxParts.getBlockFormContent( props ),
						);

						handlers.updateCopyPasteContent();

						$( window ).trigger( 'wpformsFormSelectorEdit', [ props ] );

						return jsx;
					}

					// Block preview picture.
					if ( attributes.preview ) {
						jsx.push(
							app.jsxParts.getBlockPreview(),
						);

						return jsx;
					}

					// Block placeholder (form selector).
					jsx.push(
						app.jsxParts.getBlockPlaceholder( props.attributes, handlers, formOptions ),
					);

					return jsx;
				},
				save: () => null,
			} );
		},

		/**
		 * Init default style settings.
		 *
		 * @since 1.8.1
		 */
		initDefaults: function() {

			[ 'formId', 'copyPasteValue' ].forEach( key => delete defaultStyleSettings[ key ] );
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
			getMainSettings: function( attributes, handlers, formOptions ) {

				return (
					<InspectorControls key="wpforms-gutenberg-form-selector-inspector-main-settings">
						<PanelBody className="wpforms-gutenberg-panel" title={ strings.form_settings }>
							<SelectControl
								label={ strings.form_selected }
								value={ attributes.formId }
								options={ formOptions }
								onChange={ value => handlers.attrChange( 'formId', value ) }
							/>
							<ToggleControl
								label={ strings.show_title }
								checked={ attributes.displayTitle }
								onChange={ value => handlers.attrChange( 'displayTitle', value ) }
							/>
							<ToggleControl
								label={ strings.show_description }
								checked={ attributes.displayDesc }
								onChange={ value => handlers.attrChange( 'displayDesc', value ) }
							/>
							<p className="wpforms-gutenberg-panel-notice">
								<strong>{ strings.panel_notice_head }</strong>
								{ strings.panel_notice_text }
								<a href={strings.panel_notice_link} rel="noreferrer" target="_blank">{ strings.panel_notice_link_text }</a>
							</p>
						</PanelBody>
					</InspectorControls>
				);
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
			getFieldStyles: function( attributes, handlers, sizeOptions ) { // eslint-disable-line max-lines-per-function

				return (
					<PanelBody className={ app.getPanelClass( attributes ) } title={ strings.field_styles }>
						<p className="wpforms-gutenberg-panel-notice wpforms-use-modern-notice">
							<strong>{ strings.use_modern_notice_head }</strong>
							{ strings.use_modern_notice_text } <a href={strings.use_modern_notice_link} rel="noreferrer" target="_blank">{ strings.learn_more }</a>
						</p>

						<p className="wpforms-gutenberg-panel-notice wpforms-warning wpforms-lead-form-notice" style={{ display: 'none' }}>
							<strong>{ strings.lead_forms_panel_notice_head }</strong>
							{ strings.lead_forms_panel_notice_text }
						</p>

						<Flex gap={4} align="flex-start" className={'wpforms-gutenberg-form-selector-flex'} justify="space-between">
							<FlexBlock>
								<SelectControl
									label={ strings.size }
									value={ attributes.fieldSize }
									options={ sizeOptions }
									onChange={ value => handlers.styleAttrChange( 'fieldSize', value ) }
								/>
							</FlexBlock>
							<FlexBlock>
								<__experimentalUnitControl
									label={ strings.border_radius }
									value={ attributes.fieldBorderRadius }
									isUnitSelectTabbable
									onChange={ value => handlers.styleAttrChange( 'fieldBorderRadius', value ) }
								/>
							</FlexBlock>
						</Flex>

						<div className="wpforms-gutenberg-form-selector-color-picker">
							<div className="wpforms-gutenberg-form-selector-control-label">{ strings.colors }</div>
							<PanelColorSettings
								__experimentalIsRenderedInSidebar
								enableAlpha
								showTitle={ false }
								className="wpforms-gutenberg-form-selector-color-panel"
								colorSettings={[
									{
										value: attributes.fieldBackgroundColor,
										onChange: value => handlers.styleAttrChange( 'fieldBackgroundColor', value ),
										label: strings.background,
									},
									{
										value: attributes.fieldBorderColor,
										onChange: value => handlers.styleAttrChange( 'fieldBorderColor', value ),
										label: strings.border,
									},
									{
										value: attributes.fieldTextColor,
										onChange: value => handlers.styleAttrChange( 'fieldTextColor', value ),
										label: strings.text,
									},
								]}
							/>
						</div>
					</PanelBody>
				);
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
			getLabelStyles: function( attributes, handlers, sizeOptions ) {

				return (
					<PanelBody className={ app.getPanelClass( attributes ) } title={ strings.label_styles }>
						<SelectControl
							label={ strings.size }
							value={ attributes.labelSize }
							className="wpforms-gutenberg-form-selector-fix-bottom-margin"
							options={ sizeOptions}
							onChange={ value => handlers.styleAttrChange( 'labelSize', value ) }
						/>

						<div className="wpforms-gutenberg-form-selector-color-picker">
							<div className="wpforms-gutenberg-form-selector-control-label">{ strings.colors }</div>
							<PanelColorSettings
								__experimentalIsRenderedInSidebar
								enableAlpha
								showTitle={ false }
								className="wpforms-gutenberg-form-selector-color-panel"
								colorSettings={[
									{
										value: attributes.labelColor,
										onChange: value => handlers.styleAttrChange( 'labelColor', value ),
										label: strings.label,
									},
									{
										value: attributes.labelSublabelColor,
										onChange: value => handlers.styleAttrChange( 'labelSublabelColor', value ),
										label: strings.sublabel_hints.replace( '&amp;', '&' ),
									},
									{
										value: attributes.labelErrorColor,
										onChange: value => handlers.styleAttrChange( 'labelErrorColor', value ),
										label: strings.error_message,
									},
								]}
							/>
						</div>
					</PanelBody>
				);
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
			getButtonStyles: function( attributes, handlers, sizeOptions ) {

				return (
					<PanelBody className={ app.getPanelClass( attributes ) } title={ strings.button_styles }>
						<Flex gap={4} align="flex-start" className={'wpforms-gutenberg-form-selector-flex'} justify="space-between">
							<FlexBlock>
								<SelectControl
									label={ strings.size }
									value={ attributes.buttonSize }
									options={ sizeOptions }
									onChange={ value => handlers.styleAttrChange( 'buttonSize', value ) }
								/>
							</FlexBlock>
							<FlexBlock>
								<__experimentalUnitControl
									onChange={ value => handlers.styleAttrChange( 'buttonBorderRadius', value ) }
									label={ strings.border_radius }
									isUnitSelectTabbable
									value={ attributes.buttonBorderRadius } />
							</FlexBlock>
						</Flex>

						<div className="wpforms-gutenberg-form-selector-color-picker">
							<div className="wpforms-gutenberg-form-selector-control-label">{ strings.colors }</div>
							<PanelColorSettings
								__experimentalIsRenderedInSidebar
								enableAlpha
								showTitle={ false }
								className="wpforms-gutenberg-form-selector-color-panel"
								colorSettings={[
									{
										value: attributes.buttonBackgroundColor,
										onChange: value => handlers.styleAttrChange( 'buttonBackgroundColor', value ),
										label: strings.background,
									},
									{
										value: attributes.buttonTextColor,
										onChange: value => handlers.styleAttrChange( 'buttonTextColor', value ),
										label: strings.text,
									},
								]} />
							<div className="wpforms-gutenberg-form-selector-legend wpforms-button-color-notice">
								{ strings.button_color_notice }
							</div>
						</div>
					</PanelBody>
				);
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
			getStyleSettings: function( attributes, handlers, sizeOptions ) {

				return (
					<InspectorControls key="wpforms-gutenberg-form-selector-style-settings">
						{ app.jsxParts.getFieldStyles( attributes, handlers, sizeOptions ) }
						{ app.jsxParts.getLabelStyles( attributes, handlers, sizeOptions ) }
						{ app.jsxParts.getButtonStyles( attributes, handlers, sizeOptions ) }
					</InspectorControls>
				);
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
			getAdvancedSettings: function( attributes, handlers ) {

				const [ isOpen, setOpen ] = useState( false );
				const openModal = () => setOpen( true );
				const closeModal = () => setOpen( false );

				return (
					<InspectorAdvancedControls>
						<div className={ app.getPanelClass( attributes ) }>
							<TextareaControl
								label={ strings.copy_paste_settings }
								rows="4"
								spellCheck="false"
								value={ attributes.copyPasteValue }
								onChange={ value => handlers.pasteSettings( value ) }
							/>
							<div className="wpforms-gutenberg-form-selector-legend" dangerouslySetInnerHTML={{ __html: strings.copy_paste_notice }}></div>

							<Button className='wpforms-gutenberg-form-selector-reset-button' onClick={ openModal }>{ strings.reset_style_settings }</Button>
						</div>

						{ isOpen && (
							<Modal  className="wpforms-gutenberg-modal"
								title={ strings.reset_style_settings}
								onRequestClose={ closeModal }>

								<p>{ strings.reset_settings_confirm_text }</p>

								<Flex gap={3} align="center" justify="flex-end">
									<Button isSecondary onClick={ closeModal }>
										{strings.btn_no}
									</Button>

									<Button isPrimary onClick={ () => {
										closeModal();
										handlers.resetSettings();
									} }>
										{ strings.btn_yes_reset }
									</Button>
								</Flex>
							</Modal>
						) }
					</InspectorAdvancedControls>
				);
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
			getBlockFormContent: function( props ) {

				if ( triggerServerRender ) {

					return (
						<ServerSideRender
							key="wpforms-gutenberg-form-selector-server-side-renderer"
							block="wpforms/form-selector"
							attributes={ props.attributes }
						/>
					);
				}

				const clientId = props.clientId;
				const block = app.getBlockContainer( props );

				// In the case of empty content, use server side renderer.
				// This happens when the block is duplicated or converted to a reusable block.
				if ( ! block || ! block.innerHTML ) {
					triggerServerRender = true;

					return app.jsxParts.getBlockFormContent( props );
				}

				blocks[ clientId ] = blocks[ clientId ] || {};
				blocks[ clientId ].blockHTML = block.innerHTML;
				blocks[ clientId ].loadedFormId = props.attributes.formId;

				return (
					<Fragment key="wpforms-gutenberg-form-selector-fragment-form-html">
						<div dangerouslySetInnerHTML={{ __html: blocks[ clientId ].blockHTML }} />
					</Fragment>
				);
			},

			/**
			 * Get block preview JSX code.
			 *
			 * @since 1.8.1
			 *
			 * @returns {JSX.Element} Block preview JSX code.
			 */
			getBlockPreview: function() {

				return (
					<Fragment
						key="wpforms-gutenberg-form-selector-fragment-block-preview">
						<img src={ wpforms_gutenberg_form_selector.block_preview_url } style={{ width: '100%' }} />
					</Fragment>
				);
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
			getBlockPlaceholder: function( attributes, handlers, formOptions ) {

				return (
					<Placeholder
						key="wpforms-gutenberg-form-selector-wrap"
						className="wpforms-gutenberg-form-selector-wrap">
						<img src={wpforms_gutenberg_form_selector.logo_url} />
						<h3>{ strings.title }</h3>
						<SelectControl
							key="wpforms-gutenberg-form-selector-select-control"
							value={ attributes.formId }
							options={ formOptions }
							onChange={ value => handlers.attrChange( 'formId', value ) }
						/>
					</Placeholder>
				);
			},
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
		getPanelClass: function( attributes ) {

			let cssClass = 'wpforms-gutenberg-panel wpforms-block-settings-' + attributes.clientId;

			if ( ! app.isFullStylingEnabled() ) {
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
		isFullStylingEnabled: function() {

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
		getBlockContainer: function( props ) {

			const blockSelector = `#block-${props.clientId} > div`;
			let block = document.querySelector( blockSelector );

			// For FSE / Gutenberg plugin we need to take a look inside the iframe.
			if ( ! block ) {
				const editorCanvas = document.querySelector( 'iframe[name="editor-canvas"]' );

				block = editorCanvas && editorCanvas.contentWindow.document.querySelector( blockSelector );
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
		getSettingsFieldsHandlers: function( props ) { // eslint-disable-line max-lines-per-function

			return {

				/**
				 * Field style attribute change event handler.
				 *
				 * @since 1.8.1
				 *
				 * @param {string} attribute Attribute name.
				 * @param {string} value     New attribute value.
				 */
				styleAttrChange: function( attribute, value ) {

					const block = app.getBlockContainer( props ),
						container = block.querySelector( `#wpforms-${props.attributes.formId}` ),
						property = attribute.replace( /[A-Z]/g, letter => `-${letter.toLowerCase()}` ),
						setAttr = {};

					if ( container ) {
						switch ( property ) {
							case 'field-size':
							case 'label-size':
							case 'button-size':
								for ( const key in sizes[ property ][ value ] ) {
									container.style.setProperty(
										`--wpforms-${property}-${key}`,
										sizes[ property ][ value ][ key ],
									);
								}

								break;

							default:
								container.style.setProperty( `--wpforms-${property}`, value );
						}
					}

					setAttr[ attribute ] = value;

					props.setAttributes( setAttr );

					triggerServerRender = false;

					this.updateCopyPasteContent();

					$( window ).trigger( 'wpformsFormSelectorStyleAttrChange', [ block, props, attribute, value ] );
				},

				/**
				 * Field regular attribute change event handler.
				 *
				 * @since 1.8.1
				 *
				 * @param {string} attribute Attribute name.
				 * @param {string} value     New attribute value.
				 */
				attrChange: function( attribute, value ) {

					const setAttr = {};

					setAttr[ attribute ] = value;

					props.setAttributes( setAttr );

					triggerServerRender = true;

					this.updateCopyPasteContent();
				},

				/**
				 * Reset Form Styles settings to defaults.
				 *
				 * @since 1.8.1
				 */
				resetSettings: function() {

					for ( let key in defaultStyleSettings ) {
						this.styleAttrChange( key, defaultStyleSettings[ key ] );
					}
				},

				/**
				 * Update content of the "Copy/Paste" fields.
				 *
				 * @since 1.8.1
				 */
				updateCopyPasteContent: function() {

					let content = {};
					let atts = wp.data.select( 'core/block-editor' ).getBlockAttributes( props.clientId );

					for ( let key in defaultStyleSettings ) {
						content[key] = atts[ key ];
					}

					props.setAttributes( { 'copyPasteValue': JSON.stringify( content ) } );
				},

				/**
				 * Paste settings handler.
				 *
				 * @since 1.8.1
				 *
				 * @param {string} value New attribute value.
				 */
				pasteSettings: function( value ) {

					let pasteAttributes = app.parseValidateJson( value );

					if ( ! pasteAttributes ) {

						wp.data.dispatch( 'core/notices' ).createErrorNotice(
							strings.copy_paste_error,
							{ id: 'wpforms-json-parse-error' }
						);

						this.updateCopyPasteContent();

						return;
					}

					pasteAttributes.copyPasteValue = value;

					props.setAttributes( pasteAttributes );

					triggerServerRender = true;
				},
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
		parseValidateJson: function( value ) {

			if ( typeof value !== 'string' ) {
				return false;
			}

			let atts;

			try {
				atts = JSON.parse( value );
			} catch ( error ) {
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
		getIcon: function() {

			return createElement(
				'svg',
				{ width: 20, height: 20, viewBox: '0 0 612 612', className: 'dashicon' },
				createElement(
					'path',
					{
						fill: 'currentColor',
						d: 'M544,0H68C30.445,0,0,30.445,0,68v476c0,37.556,30.445,68,68,68h476c37.556,0,68-30.444,68-68V68 C612,30.445,581.556,0,544,0z M464.44,68L387.6,120.02L323.34,68H464.44z M288.66,68l-64.26,52.02L147.56,68H288.66z M544,544H68 V68h22.1l136,92.14l79.9-64.6l79.56,64.6l136-92.14H544V544z M114.24,263.16h95.88v-48.28h-95.88V263.16z M114.24,360.4h95.88 v-48.62h-95.88V360.4z M242.76,360.4h255v-48.62h-255V360.4L242.76,360.4z M242.76,263.16h255v-48.28h-255V263.16L242.76,263.16z M368.22,457.3h129.54V408H368.22V457.3z',
					},
				),
			);
		},

		/**
		 * Get block attributes.
		 *
		 * @since 1.8.1
		 *
		 * @returns {object} Block attributes.
		 */
		getBlockAttributes: function() { // eslint-disable-line max-lines-per-function

			return {
				clientId: {
					type: 'string',
					default: '',
				},
				formId: {
					type: 'string',
					default: defaults.formId,
				},
				displayTitle: {
					type: 'boolean',
					default: defaults.displayTitle,
				},
				displayDesc: {
					type: 'boolean',
					default: defaults.displayDesc,
				},
				preview: {
					type: 'boolean',
				},
				fieldSize: {
					type: 'string',
					default: defaults.fieldSize,
				},
				fieldBorderRadius: {
					type: 'string',
					default: defaults.fieldBorderRadius,
				},
				fieldBackgroundColor: {
					type: 'string',
					default: defaults.fieldBackgroundColor,
				},
				fieldBorderColor: {
					type: 'string',
					default: defaults.fieldBorderColor,
				},
				fieldTextColor: {
					type: 'string',
					default: defaults.fieldTextColor,
				},
				labelSize: {
					type: 'string',
					default: defaults.labelSize,
				},
				labelColor: {
					type: 'string',
					default: defaults.labelColor,
				},
				labelSublabelColor: {
					type: 'string',
					default: defaults.labelSublabelColor,
				},
				labelErrorColor: {
					type: 'string',
					default: defaults.labelErrorColor,
				},
				buttonSize: {
					type: 'string',
					default: defaults.buttonSize,
				},
				buttonBorderRadius: {
					type: 'string',
					default: defaults.buttonBorderRadius,
				},
				buttonBackgroundColor: {
					type: 'string',
					default: defaults.buttonBackgroundColor,
				},
				buttonTextColor: {
					type: 'string',
					default: defaults.buttonTextColor,
				},
				copyPasteValue: {
					type: 'string',
					default: defaults.copyPasteValue,
				},
			};
		},

		/**
		 * Get form selector options.
		 *
		 * @since 1.8.1
		 *
		 * @returns {Array} Form options.
		 */
		getFormOptions: function() {

			const formOptions = wpforms_gutenberg_form_selector.forms.map( value => (
				{ value: value.ID, label: value.post_title }
			) );

			formOptions.unshift( { value: '', label: strings.form_select } );

			return formOptions;
		},

		/**
		 * Get size selector options.
		 *
		 * @since 1.8.1
		 *
		 * @returns {Array} Size options.
		 */
		getSizeOptions: function() {

			return [
				{
					label: strings.small,
					value: 'small',
				},
				{
					label: strings.medium,
					value: 'medium',
				},
				{
					label: strings.large,
					value: 'large',
				},
			];
		},

		/**
		 * Event `wpformsFormSelectorEdit` handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e     Event object.
		 * @param {object} props Block properties.
		 */
		blockEdit: function( e, props ) {

			const block = app.getBlockContainer( props );

			if ( ! block || ! block.dataset ) {
				return;
			}

			app.initLeadFormSettings( block.parentElement );
		},

		/**
		 * Init Lead Form Settings panels.
		 *
		 * @since 1.8.1
		 *
		 * @param {Element} block Block element.
		 */
		initLeadFormSettings: function( block ) {

			if ( ! block || ! block.dataset ) {
				return;
			}

			if ( ! app.isFullStylingEnabled() ) {
				return;
			}

			const clientId = block.dataset.block;
			const $form = $( block.querySelector( '.wpforms-container' ) );
			const $panel = $( `.wpforms-block-settings-${clientId}` );

			if ( $form.hasClass( 'wpforms-lead-forms-container' ) ) {

				$panel
					.addClass( 'disabled_panel' )
					.find( '.wpforms-gutenberg-panel-notice.wpforms-lead-form-notice' )
					.css( 'display', 'block' );

				$panel
					.find( '.wpforms-gutenberg-panel-notice.wpforms-use-modern-notice' )
					.css( 'display', 'none' );

				return;
			}

			$panel
				.removeClass( 'disabled_panel' )
				.find( '.wpforms-gutenberg-panel-notice.wpforms-lead-form-notice' )
				.css( 'display', 'none' );

			$panel
				.find( '.wpforms-gutenberg-panel-notice.wpforms-use-modern-notice' )
				.css( 'display', null );
		},

		/**
		 * Event `wpformsFormSelectorFormLoaded` handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e Event object.
		 */
		formLoaded: function( e ) {

			app.initLeadFormSettings( e.detail.block );
			app.updateAccentColors( e.detail );
			app.loadChoicesJS( e.detail );
			app.initRichTextField( e.detail.formId );

			$( e.detail.block )
				.off( 'click' )
				.on( 'click', app.blockClick );
		},

		/**
		 * Click on the block event handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e Event object.
		 */
		blockClick: function( e ) {

			app.initLeadFormSettings( e.currentTarget );
		},

		/**
		 * Update accent colors of some fields in GB block in Modern Markup mode.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} detail Event details object.
		 */
		updateAccentColors: function( detail ) {

			if (
				! wpforms_gutenberg_form_selector.is_modern_markup ||
				! window.WPForms ||
				! window.WPForms.FrontendModern ||
				! detail.block
			) {
				return;
			}

			const $form = $( detail.block.querySelector( `#wpforms-${detail.formId}` ) ),
				FrontendModern = window.WPForms.FrontendModern;

			FrontendModern.updateGBBlockPageIndicatorColor( $form );
			FrontendModern.updateGBBlockIconChoicesColor( $form );
			FrontendModern.updateGBBlockRatingColor( $form );
		},

		/**
		 * Init Modern style Dropdown fields (<select>).
		 *
		 * @since 1.8.1
		 *
		 * @param {object} detail Event details object.
		 */
		loadChoicesJS: function( detail ) {

			if ( typeof window.Choices !== 'function' ) {
				return;
			}

			const $form = $( detail.block.querySelector( `#wpforms-${detail.formId}` ) );

			$form.find( '.choicesjs-select' ).each( function( idx, el ) {

				const $el = $( el );

				if ( $el.data( 'choice' ) === 'active' ) {
					return;
				}

				var args = window.wpforms_choicesjs_config || {},
					searchEnabled = $el.data( 'search-enabled' ),
					$field = $el.closest( '.wpforms-field' );

				args.searchEnabled = 'undefined' !== typeof searchEnabled ? searchEnabled : true;
				args.callbackOnInit = function() {

					var self = this,
						$element = $( self.passedElement.element ),
						$input = $( self.input.element ),
						sizeClass = $element.data( 'size-class' );

					// Add CSS-class for size.
					if ( sizeClass ) {
						$( self.containerOuter.element ).addClass( sizeClass );
					}

					/**
					 * If a multiple select has selected choices - hide a placeholder text.
					 * In case if select is empty - we return placeholder text back.
					 */
					if ( $element.prop( 'multiple' ) ) {

						// On init event.
						$input.data( 'placeholder', $input.attr( 'placeholder' ) );

						if ( self.getValue( true ).length ) {
							$input.removeAttr( 'placeholder' );
						}
					}

					this.disable();
					$field.find( '.is-disabled' ).removeClass( 'is-disabled' );
				};

				try {
					const choicesInstance =  new Choices( el, args );

					// Save Choices.js instance for future access.
					$el.data( 'choicesjs', choicesInstance );

				} catch ( e ) {} // eslint-disable-line no-empty
			} );
		},

		/**
		 * Initialize RichText field.
		 *
		 * @since 1.8.1
		 *
		 * @param {int} formId Form ID.
		 */
		initRichTextField: function( formId ) {

			// Set default tab to `Visual`.
			$( `#wpforms-${formId} .wp-editor-wrap` ).removeClass( 'html-active' ).addClass( 'tmce-active' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.FormSelector.init();
