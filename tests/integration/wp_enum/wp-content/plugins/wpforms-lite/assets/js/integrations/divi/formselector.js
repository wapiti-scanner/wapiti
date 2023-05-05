/* global wpforms_divi_builder */

import React, { Component } from 'react';
import PropTypes from 'prop-types';


/**
 * WPFormsSelector component.
 *
 * @since 1.6.3
 */
class WPFormsSelector extends Component {

	/**
	 * Module slug.
	 *
	 * @since 1.6.3
	 *
	 * @type {string}
	 */
	static slug = 'wpforms_selector';

	/**
	 * Constructor.
	 *
	 * @since 1.6.3
	 *
	 * @param {string} props List of properties.
	 */
	constructor( props ) {

		super( props );

		this.state = {
			error: null,
			isLoading: true,
			form: null,
		};
	}

	/**
	 * Set types for properties.
	 *
	 * @since 1.6.3
	 *
	 * @returns {object} Properties type.
	 */
	static get propTypes() {

		return {
			form_id: PropTypes.number, // eslint-disable-line camelcase
			show_title: PropTypes.string, // eslint-disable-line camelcase
			show_desc: PropTypes.string, // eslint-disable-line camelcase
		};
	}

	/**
	 * Check if form settings was updated.
	 *
	 * @since 1.6.3
	 *
	 * @param {object} prevProps List of previous properties.
	 */
	componentDidUpdate( prevProps ) {

		if ( prevProps.form_id !== this.props.form_id || prevProps.show_title !== this.props.show_title || prevProps.show_desc !== this.props.show_desc ) {
			this.componentDidMount();
		}
	}

	/**
	 * Ajax request for form HTML.
	 *
	 * @since 1.6.3
	 */
	componentDidMount() {

		var formData = new FormData();

		formData.append( 'nonce', wpforms_divi_builder.nonce );
		formData.append( 'action', 'wpforms_divi_preview' );
		formData.append( 'form_id', this.props.form_id );
		formData.append( 'show_title', this.props.show_title );
		formData.append( 'show_desc', this.props.show_desc );

		fetch(
			wpforms_divi_builder.ajax_url,
			{
				method: 'POST',
				cache: 'no-cache',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					'Cache-Control': 'no-cache',
				},
				body: new URLSearchParams( formData ),
			},
		)
			.then( res => res.json() )
			.then(
				( result ) => {

					this.setState( {
						isLoading: false,
						form: result.data,
					} );
				},
				( error ) => {

					this.setState( {
						isLoading: false,
						error,
					} );
				},
			);
	}

	/**
	 * Render module view.
	 *
	 * @since 1.6.3
	 *
	 * @returns {JSX.Element} View for module.
	 */
	render() {

		var { error, isLoaded, form } = this.state,
			wrapperClasses = isLoaded ? 'wpforms-divi-form-preview loading' : 'wpforms-divi-form-preview';

		if ( error || ! form ) {

			return (
				<div className="wpforms-divi-form-placeholder">
					<img src={wpforms_divi_builder.placeholder}/>
					<h3>{wpforms_divi_builder.placeholder_title}</h3>
				</div>
			);
		}

		return (
			<div className={wrapperClasses}>
				{<div dangerouslySetInnerHTML={{ __html: form }}/>}
			</div>
		);
	}
}

jQuery( window )

	// Register custom modules.
	.on( 'et_builder_api_ready', ( event, API ) => {
		API.registerModules( [ WPFormsSelector ] );
	} )

	// Re-initialize WPForms frontend.
	.on( 'wpformsDiviModuleDisplay', ( event ) => {
		window.wpforms.init();
	} );

// Make all the modern dropdowns disabled.
jQuery( document )
	.on( 'wpformsReady', ( event ) => {

		var $ = jQuery;

		$( '.choicesjs-select' ).each( function() {

			var $instance = $( this ).data( 'choicesjs' );

			if ( ! $instance || typeof $instance.disable !== 'function' ) {
				return;
			}

			$instance.disable();
		} );
	} );
