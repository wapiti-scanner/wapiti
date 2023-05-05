/* global wpforms_admin, WPFormsFormTemplates, wpforms_admin_form_templates */

/**
 * Admin Sub-page Form Templates function.
 *
 * @since 1.7.7
 */

'use strict';

var WPFormsAdminFormTemplates = window.WPFormsAdminFormTemplates || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	let app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.7
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.7.7
		 */
		ready: function() {

			app.events();
		},

		/**
		 * Bind events.
		 *
		 * @since 1.7.7
		 */
		events: function() {

			$( '.wpforms-form-setup-content' )
				.on( 'keyup', '#wpforms-setup-template-search', WPFormsFormTemplates.searchTemplate )
				.on( 'click', '.wpforms-setup-templates-categories li', WPFormsFormTemplates.selectCategory )
				.on( 'click', '.wpforms-template-select', app.selectTemplate )
				.on( 'click', '.wpforms-trigger-blank', app.selectBlankTemplate );
		},

		/**
		 * Select template.
		 *
		 * @since 1.7.7
		 *
		 * @param {object} e Event object.
		 */
		selectTemplate: function( e ) {

			e.preventDefault();

			let $button = $( this ),
				spinner = '<i class="wpforms-loading-spinner wpforms-loading-white wpforms-loading-inline"></i>';

			// Don't do anything for templates that trigger education modal OR addons-modal.
			if ( $button.hasClass( 'education-modal' ) ) {
				return;
			}

			$( '.wpforms-form-setup-content' ).find( '.wpforms-template' ).removeClass( 'active' );
			$button.closest( '.wpforms-template' ).addClass( 'active' );

			// Save original label.
			$button.data( 'labelOriginal', $button.html() );

			// Display loading indicator.
			$button.html( spinner + wpforms_admin.loading );

			app.selectTemplateProcessAjax( $button.data( 'template-name-raw' ), $button.data( 'template' ) );
		},

		/**
		 * Select Blank template.
		 *
		 * @since 1.7.7
		 *
		 * @param {object} e Event object.
		 */
		selectBlankTemplate: function( e ) {

			e.preventDefault();

			app.selectTemplateProcessAjax( 'Blank Form', 'blank' );
		},

		/**
		 * Select template. Create or update form AJAX call.
		 *
		 * @since 1.7.7
		 *
		 * @param {string} formName Name of the form.
		 * @param {string} template Template slug.
		 */
		selectTemplateProcessAjax: function( formName, template ) {

			let data = {
				title: formName,
				action: 'wpforms_new_form',
				template: template,
				// eslint-disable-next-line camelcase
				form_id: 0,
				nonce: wpforms_admin_form_templates.nonce,
			};

			$.post( wpforms_admin.ajax_url, data )
				.done( function( res ) {

					if ( res.success ) {
						window.location.href = res.data.redirect;

						return;
					}

					if ( res.data.error_type === 'invalid_template' ) {
						app.selectTemplateProcessInvalidTemplateError( res.data.message, formName );

						return;
					}

					app.selectTemplateProcessError( res.data.message );
				} )
				.fail( function( xhr, textStatus, e ) {

					app.selectTemplateProcessError( '' );
				} );
		},

		/**
		 * Select template AJAX call error modal for invalid template using.
		 *
		 * @since 1.7.7
		 *
		 * @param {string} errorMessage Error message.
		 * @param {string} formName     Name of the form.
		 */
		selectTemplateProcessInvalidTemplateError: function( errorMessage, formName ) {

			$.alert( {
				title: wpforms_admin.heads_up,
				content: errorMessage,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				boxWidth: '600px',
				buttons: {
					confirm: {
						text: wpforms_admin.use_simple_contact_form,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							app.selectTemplateProcessAjax( formName, 'simple-contact-form-template' );
						},
					},
					cancel: {
						text: wpforms_admin.cancel,
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
						},
					},
				},
			} );
		},

		/**
		 * Select template AJAX call error modal.
		 *
		 * @since 1.7.7
		 *
		 * @param {string} error Error message.
		 */
		selectTemplateProcessError: function( error ) {

			var content = error && error.length ? '<p>' + error + '</p>' : '';

			$.alert( {
				title: wpforms_admin.heads_up,
				content: wpforms_admin.error_select_template + content,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
						},
					},
				},
			} );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsAdminFormTemplates.init();
