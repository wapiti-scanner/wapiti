/* global wpforms_gutenberg_form_selector */
/* jshint es3: false, esversion: 6 */

'use strict';

const { serverSideRender: ServerSideRender = wp.components.ServerSideRender } = wp;
const { createElement, Fragment } = wp.element;
const { registerBlockType } = wp.blocks;
const { InspectorControls } = wp.blockEditor || wp.editor;
const { SelectControl, ToggleControl, PanelBody, Placeholder } = wp.components;

const wpformsIcon = createElement( 'svg', { width: 20, height: 20, viewBox: '0 0 612 612', className: 'dashicon' },
	createElement( 'path', {
		fill: 'currentColor',
		d: 'M544,0H68C30.445,0,0,30.445,0,68v476c0,37.556,30.445,68,68,68h476c37.556,0,68-30.444,68-68V68 C612,30.445,581.556,0,544,0z M464.44,68L387.6,120.02L323.34,68H464.44z M288.66,68l-64.26,52.02L147.56,68H288.66z M544,544H68 V68h22.1l136,92.14l79.9-64.6l79.56,64.6l136-92.14H544V544z M114.24,263.16h95.88v-48.28h-95.88V263.16z M114.24,360.4h95.88 v-48.62h-95.88V360.4z M242.76,360.4h255v-48.62h-255V360.4L242.76,360.4z M242.76,263.16h255v-48.28h-255V263.16L242.76,263.16z M368.22,457.3h129.54V408H368.22V457.3z',
	} )
);

registerBlockType( 'wpforms/form-selector', {
	title: wpforms_gutenberg_form_selector.strings.title,
	description: wpforms_gutenberg_form_selector.strings.description,
	icon: wpformsIcon,
	keywords: wpforms_gutenberg_form_selector.strings.form_keywords,
	category: 'widgets',
	attributes: {
		formId: {
			type: 'string',
		},
		displayTitle: {
			type: 'boolean',
		},
		displayDesc: {
			type: 'boolean',
		},
		preview: {
			type: 'boolean',
		},
	},
	example: {
		attributes: {
			preview: true,
		},
	},
	edit( props ) { // eslint-disable-line max-lines-per-function
		const { attributes: { formId = '', displayTitle = false, displayDesc = false, preview = false }, setAttributes } = props;
		const formOptions = wpforms_gutenberg_form_selector.forms.map( value => (
			{ value: value.ID, label: value.post_title }
		) );
		const strings = wpforms_gutenberg_form_selector.strings;
		let jsx;

		formOptions.unshift( { value: '', label: wpforms_gutenberg_form_selector.strings.form_select } );

		function selectForm( value ) { // eslint-disable-line jsdoc/require-jsdoc
			setAttributes( { formId: value } );
		}

		function toggleDisplayTitle( value ) { // eslint-disable-line jsdoc/require-jsdoc
			setAttributes( { displayTitle: value } );
		}

		function toggleDisplayDesc( value ) { // eslint-disable-line jsdoc/require-jsdoc
			setAttributes( { displayDesc: value } );
		}

		jsx = [
			<InspectorControls key="wpforms-gutenberg-form-selector-inspector-controls">
				<PanelBody title={ wpforms_gutenberg_form_selector.strings.form_settings }>
					<SelectControl
						label={ wpforms_gutenberg_form_selector.strings.form_selected }
						value={ formId }
						options={ formOptions }
						onChange={ selectForm }
					/>
					<ToggleControl
						label={ wpforms_gutenberg_form_selector.strings.show_title }
						checked={ displayTitle }
						onChange={ toggleDisplayTitle }
					/>
					<ToggleControl
						label={ wpforms_gutenberg_form_selector.strings.show_description }
						checked={ displayDesc }
						onChange={ toggleDisplayDesc }
					/>
					<p className="wpforms-gutenberg-panel-notice">
						<strong>{ strings.update_wp_notice_head }</strong>
						{ strings.update_wp_notice_text } <a href={strings.update_wp_notice_link} rel="noreferrer" target="_blank">{ strings.learn_more }</a>
					</p>

				</PanelBody>
			</InspectorControls>,
		];

		if ( formId ) {
			jsx.push(
				<ServerSideRender
					key="wpforms-gutenberg-form-selector-server-side-renderer"
					block="wpforms/form-selector"
					attributes={ props.attributes }
				/>
			);
		} else if ( preview ) {
			jsx.push(
				<Fragment
					key="wpforms-gutenberg-form-selector-fragment-block-preview">
					<img src={ wpforms_gutenberg_form_selector.block_preview_url } style={{ width: '100%' }}/>
				</Fragment>
			);
		} else {
			jsx.push(
				<Placeholder
					key="wpforms-gutenberg-form-selector-wrap"
					className="wpforms-gutenberg-form-selector-wrap">
					<img src={ wpforms_gutenberg_form_selector.logo_url }/>
					<h3>{ wpforms_gutenberg_form_selector.strings.title }</h3>
					<SelectControl
						key="wpforms-gutenberg-form-selector-select-control"
						value={ formId }
						options={ formOptions }
						onChange={ selectForm }
					/>
				</Placeholder>
			);
		}

		return jsx;
	},
	save() {
		return null;
	},
} );
