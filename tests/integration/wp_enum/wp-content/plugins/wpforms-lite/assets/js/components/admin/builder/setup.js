/* global List, wpforms_builder, wpforms_addons, wpf, WPFormsBuilder, wpforms_education, WPFormsFormTemplates */

/**
 * Form Builder Setup Panel module.
 *
 * @since 1.6.8
 */

'use strict';

var WPForms = window.WPForms || {};

WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.Setup = WPForms.Admin.Builder.Setup || ( function( document, window, $ ) {

	/**
	 * Elements holder.
	 *
	 * @since 1.6.8
	 *
	 * @type {object}
	 */
	var el = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.6.8
	 *
	 * @type {object}
	 */
	var vars = {};

	/**
	 * Active template name.
	 *
	 * @since 1.7.6
	 */
	const activeTemplateName = $( '.wpforms-template.selected .wpforms-template-name' ).text().trim();

	/**
	 * Public functions and properties.
	 *
	 * @since 1.6.8
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.6.8
		 */
		init: function() {

			$( app.ready );

			// Page load.
			$( window ).on( 'load', function() {

				// In the case of jQuery 3.+, we need to wait for a ready event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );
		},

		/**
		 * DOM is fully loaded.
		 *
		 * @since 1.6.8
		 */
		ready: function() {

			app.setup();
			app.setPanelsToggleState();
			app.setupTitleFocus();
			app.setTriggerBlankLink();
			app.events();

			el.$builder.trigger( 'wpformsBuilderSetupReady' );
		},

		/**
		 * Page load.
		 *
		 * @since 1.6.8
		 */
		load: function() {

			app.applyTemplateOnRequest();
		},

		/**
		 * Setup. Prepare some variables.
		 *
		 * @since 1.6.8
		 */
		setup: function() {

			// Cache DOM elements.
			el = {
				$builder: $( '#wpforms-builder' ),
				$form: $( '#wpforms-builder-form' ),
				$formName: $( '#wpforms-setup-name' ),
				$panel: $( '#wpforms-panel-setup' ),
				$categories: $( '#wpforms-panel-setup .wpforms-setup-templates-categories' ),
			};

			// Template list object.
			vars.templateList = new List( 'wpforms-setup-templates-list', {
				valueNames: [
					'wpforms-template-name',
					'wpforms-template-desc',
					{
						name: 'categories',
						attr: 'data-categories',
					},
				],
			} );

			// Other values.
			vars.spinner = '<i class="wpforms-loading-spinner wpforms-loading-white wpforms-loading-inline"></i>';
			vars.formID = el.$form.data( 'id' );
		},

		/**
		 * Bind events.
		 *
		 * @since 1.6.8
		 */
		events: function() {

			el.$panel
				.on( 'keyup', '#wpforms-setup-template-search', WPFormsFormTemplates.searchTemplate )
				.on( 'click', '.wpforms-setup-templates-categories li', WPFormsFormTemplates.selectCategory )
				.on( 'click', '.wpforms-template-select', app.selectTemplate )
				.on( 'click', '.wpforms-trigger-blank', app.selectBlankTemplate );

			// Focus on the form title field when displaying setup panel.
			el.$builder
				.on( 'wpformsPanelSwitched', app.setupTitleFocus );

			// Sync Setup title and settings title.
			el.$builder
				.on( 'input', '#wpforms-panel-field-settings-form_title', app.syncTitle )
				.on( 'input', '#wpforms-setup-name', app.syncTitle );

		},

		/**
		 * Set panels toggle buttons state.
		 *
		 * @since 1.6.8
		 */
		setPanelsToggleState: function() {

			el.$builder
				.find( '#wpforms-panels-toggle button:not(.active)' )
				.toggleClass( 'wpforms-disabled', vars.formID === '' );
		},

		/**
		 * Set attributes of "blank template" link.
		 *
		 * @since 1.6.8
		 */
		setTriggerBlankLink: function() {

			el.$builder
				.find( '.wpforms-trigger-blank' )
				.attr( {
					'data-template-name-raw': 'Blank Form',
					'data-template': 'blank',
				} );
		},

		/**
		 * Force focus on the form title field when switched to the Setup panel.
		 *
		 * @since 1.6.8
		 *
		 * @param {object} e    Event object.
		 * @param {string} view Current view.
		 */
		setupTitleFocus: function( e, view ) {

			if ( typeof view === 'undefined' ) {
				view = wpf.getQueryString( 'view' );
			}

			if ( view === 'setup' ) {
				el.$formName.trigger( 'focus' );
			}
		},

		/**
		 * Keep Setup title and settings title instances the same.
		 *
		 * @since 1.6.8
		 *
		 * @param {object} e Event object.
		 */
		syncTitle: function( e ) {

			if ( e.target.id === 'wpforms-setup-name' ) {
				$( '#wpforms-panel-field-settings-form_title' ).val( e.target.value );
			} else {
				$( '#wpforms-setup-name' ).val( e.target.value );
			}
		},

		/**
		 * Search template.
		 *
		 * @since 1.6.8
		 * @since 1.7.7 Deprecated.
		 *
		 * @deprecated Use `WPFormsFormTemplates.searchTemplate` instead.
		 *
		 * @param {object} e Event object.
		 */
		searchTemplate: function( e ) {

			console.warn( 'WARNING! Function "WPForms.Admin.Builder.Setup.searchTemplate( e )" has been deprecated, please use the new "WPFormsFormTemplates.searchTemplate( e )" function instead!' );

			WPFormsFormTemplates.searchTemplate( e );
		},

		/**
		 * Select category.
		 *
		 * @since 1.6.8
		 * @since 1.7.7 Deprecated.
		 *
		 * @deprecated Use `WPFormsFormTemplates.selectCategory` instead.
		 *
		 * @param {object} e Event object.
		 */
		selectCategory: function( e ) {

			console.warn( 'WARNING! Function "WPForms.Admin.Builder.Setup.selectCategory( e )" has been deprecated, please use the new "WPFormsFormTemplates.selectCategory( e )" function instead!' );

			WPFormsFormTemplates.selectCategory( e );
		},

		/**
		 * Select template.
		 *
		 * @since 1.6.8
		 *
		 * @param {object} e Event object.
		 */
		selectTemplate: function( e ) {

			e.preventDefault();

			var $button  = $( this ),
				template = $button.data( 'template' ),
				formName = app.getFormName( $button );

			// Don't do anything for templates that trigger education modal OR addons-modal.
			if ( $button.hasClass( 'education-modal' ) ) {
				return;
			}

			el.$panel.find( '.wpforms-template' ).removeClass( 'active' );
			$button.closest( '.wpforms-template' ).addClass( 'active' );

			// Save original label.
			$button.data( 'labelOriginal', $button.html() );

			// Display loading indicator.
			$button.html( vars.spinner + wpforms_builder.loading );

			app.applyTemplate( formName, template, $button );
		},

		/**
		 * Get form name.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $button Pressed template button.
		 *
		 * @returns {string} A new form name.
		 */
		getFormName: function( $button ) {

			const templateName = $button.data( 'template-name-raw' );
			const formName = el.$formName.val();

			if ( ! formName ) {
				return templateName;
			}

			return activeTemplateName === formName ? templateName : formName;
		},

		/**
		 * Apply template.
		 *
		 * The final part of the select template routine.
		 *
		 * @since 1.6.9
		 *
		 * @param {string} formName Name of the form.
		 * @param {string} template Template slug.
		 * @param {jQuery} $button  Use template button object.
		 */
		applyTemplate: function( formName, template, $button ) {

			el.$builder.trigger( 'wpformsTemplateSelect', template );

			if ( vars.formID ) {

				// Existing form.
				app.selectTemplateExistingForm( formName, template, $button );

			} else {

				// Create a new form.
				app.selectTemplateProcess( formName, template, $button );

			}
		},

		/**
		 * Select Blank template.
		 *
		 * @since 1.6.8
		 *
		 * @param {object} e Event object.
		 */
		selectBlankTemplate: function( e ) {

			e.preventDefault();

			var $button  = $( e.target ),
				formName = el.$formName.val() || wpforms_builder.blank_form,
				template = 'blank';

			app.applyTemplate( formName, template, $button );
		},

		/**
		 * Select template. Existing form.
		 *
		 * @since 1.6.8
		 *
		 * @param {string} formName Name of the form.
		 * @param {string} template Template slug.
		 * @param {jQuery} $button  Use template button object.
		 */
		selectTemplateExistingForm: function( formName, template, $button ) {

			$.confirm( {
				title: wpforms_builder.heads_up,
				content: wpforms_builder.template_confirm,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							app.selectTemplateProcess( formName, template, $button );
						},
					},
					cancel: {
						text: wpforms_builder.cancel,
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
						},
					},
				},
			} );
		},

		/**
		 * Select template.
		 *
		 * @since 1.6.8
		 *
		 * @param {string}  formName  Name of the form.
		 * @param {string}  template  Template slug.
		 * @param {jQuery}  $button   Use template button object.
		 */
		selectTemplateProcess: function( formName, template, $button ) {

			if ( $button.data( 'addons' ) ) {
				app.addonsModal( formName, template, $button );
			} else {
				app.selectTemplateProcessAjax( formName, template );
			}
		},

		/**
		 * Cancel button click routine.
		 *
		 * @since 1.6.8
		 * @since 1.7.7 Deprecated.
		 *
		 * @deprecated Use `WPFormsFormTemplates.selectTemplateCancel` instead.
		 */
		selectTemplateCancel: function( ) {

			console.warn( 'WARNING! Function "WPForms.Admin.Builder.Setup.selectTemplateCancel" has been deprecated, please use the new "WPFormsFormTemplates.selectTemplateCancel" function instead!' );

			WPFormsFormTemplates.selectTemplateCancel();
		},

		/**
		 * Select template. Create or update form AJAX call.
		 *
		 * @since 1.6.8
		 *
		 * @param {string}  formName  Name of the form.
		 * @param {string}  template  Template slug.
		 */
		selectTemplateProcessAjax: function( formName, template ) {

			WPFormsBuilder.showLoadingOverlay();

			var data = {
				title: formName,
				action: vars.formID ? 'wpforms_update_form_template' : 'wpforms_new_form',
				template: template,
				form_id: vars.formID, // eslint-disable-line camelcase
				nonce: wpforms_builder.nonce,
			};

			$.post( wpforms_builder.ajax_url, data )
				.done( function( res ) {

					if ( res.success ) {

						// We have already warned the user that unsaved changes will be ignored.
						WPFormsBuilder.setCloseConfirmation( false );

						window.location.href = wpf.getQueryString( 'force_desktop_view' ) ?
							wpf.updateQueryString( 'force_desktop_view', 1, res.data.redirect ) :
							res.data.redirect;

						return;
					}

					wpf.debug( res );

					if ( res.data.error_type === 'invalid_template' ) {
						app.selectTemplateProcessInvalidTemplateError( res.data.message, formName );

						return;
					}

					app.selectTemplateProcessError( res.data.message );
				} )
				.fail( function( xhr, textStatus, e ) {

					wpf.debug( xhr.responseText || textStatus || '' );
					app.selectTemplateProcessError( '' );
				} );
		},

		/**
		 * Select template AJAX call error modal for invalid template using.
		 *
		 * @since 1.7.5.3
		 *
		 * @param {string} errorMessage Error message.
		 * @param {string}  formName  Name of the form.
		 */
		selectTemplateProcessInvalidTemplateError: function( errorMessage, formName ) {

			$.alert( {
				title: wpforms_builder.heads_up,
				content: errorMessage,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				boxWidth: '600px',
				buttons: {
					confirm: {
						text: wpforms_builder.use_simple_contact_form,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							app.selectTemplateProcessAjax( formName, 'simple-contact-form-template' );
							WPFormsBuilder.hideLoadingOverlay();
						},
					},
					cancel: {
						text: wpforms_builder.cancel,
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
							WPFormsBuilder.hideLoadingOverlay();
						},
					},
				},
			} );
		},

		/**
		 * Select template AJAX call error modal.
		 *
		 * @since 1.6.8
		 *
		 * @param {string} error Error message.
		 */
		selectTemplateProcessError: function( error ) {

			var content = error && error.length ? '<p>' + error + '</p>' : '';

			$.alert( {
				title: wpforms_builder.heads_up,
				content: wpforms_builder.error_select_template + content,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
							WPFormsBuilder.hideLoadingOverlay();
						},
					},
				},
			} );
		},

		/**
		 * Open required addons alert.
		 *
		 * @since 1.6.8
		 *
		 * @param {string} formName Name of the form.
		 * @param {string} template Template slug.
		 * @param {jQuery} $button  Use template button object.
		 */
		addonsModal: function( formName, template, $button ) {

			var templateName = $button.data( 'template-name-raw' ),
				addonsNames = $button.data( 'addons-names' ),
				addonsSlugs = $button.data( 'addons' ),
				addons = addonsSlugs.split( ',' ),
				prompt = addons.length > 1 ? wpforms_builder.template_addons_prompt : wpforms_builder.template_addon_prompt;

			if ( ! addons.length ) {
				return;
			}

			$.confirm( {
				title: wpforms_builder.heads_up,
				content: prompt
					.replace( /%template%/g, templateName )
					.replace( /%addons%/g, addonsNames ),
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_education.install_confirm,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							this.$$confirm
								.prop( 'disabled', true )
								.html( vars.spinner + wpforms_education.activating );

							this.$$cancel
								.prop( 'disabled', true );

							app.installActivateAddons( addons, this, formName, template );

							return false;
						},
					},
					cancel: {
						text: wpforms_education.cancel,
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
						},
					},
				},
			} );
		},

		/**
		 * Install & Activate addons via AJAX.
		 *
		 * @since 1.6.8
		 *
		 * @param {Array}  addons        Addons slugs.
		 * @param {object} previousModal Previous modal instance.
		 * @param {string} formName      Name of the form.
		 * @param {string} template      Template slug.
		 */
		installActivateAddons: function( addons, previousModal, formName, template ) {

			var ajaxResults = [],
				ajaxErrors = [],
				promiseChain = false;

			// Put each of the ajax call promise to the chain.
			addons.forEach( function( addon ) {

				if ( typeof promiseChain.done !== 'function' ) {
					promiseChain = app.installActivateAddonAjax( addon );

					return;
				}

				promiseChain = promiseChain
					.done( function( value ) {

						ajaxResults.push( value );

						return app.installActivateAddonAjax( addon );
					} )
					.fail( function( error ) {
						ajaxErrors.push( error );
					} );
			} );

			promiseChain

				// Latest promise result and error.
				.done( function( value ) {
					ajaxResults.push( value );
				} )
				.fail( function( error ) {
					ajaxErrors.push( error );
				} )

				// Finally, resolve all the promises.
				.always( function() {

					previousModal.close();

					if (
						ajaxResults.length > 0 &&
						wpf.listPluck( ajaxResults, 'success' ).every( Boolean ) && // Check if every `success` is true.
						ajaxErrors.length === 0
					) {
						app.selectTemplateProcessAjax( formName, template );
					} else {
						app.installActivateAddonsError( formName, template );
					}
				} );
		},

		/**
		 * Install & Activate addons error modal.
		 *
		 * @since 1.6.8
		 *
		 * @param {string} formName Name of the form.
		 * @param {string} template Template slug.
		 */
		installActivateAddonsError: function( formName, template ) {

			$.confirm( {
				title: wpforms_builder.heads_up,
				content: wpforms_builder.template_addons_error,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_builder.use_template,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							app.selectTemplateProcessAjax( formName, template );
						},
					},
					cancel: {
						text: wpforms_builder.cancel,
						action: function() {

							WPFormsFormTemplates.selectTemplateCancel();
						},
					},
				},
			} );
		},

		/**
		 * Install & Activate single addon via AJAX.
		 *
		 * @since 1.6.8
		 *
		 * @param {string} addon Addon slug.
		 *
		 * @returns {Promise} jQuery ajax call promise.
		 */
		installActivateAddonAjax: function( addon ) {

			var addonData = wpforms_addons[ addon ],
				deferred = new $.Deferred();

			if (
				! addonData ||
				[ 'activate', 'install' ].indexOf( addonData.action ) < 0
			) {
				deferred.resolve( false );

				return deferred.promise();
			}

			return $.post(
				wpforms_education.ajax_url,
				{
					action: 'wpforms_' + addonData.action + '_addon',
					nonce: wpforms_builder.admin_nonce,
					plugin: addonData.action === 'activate' ? addon + '/' + addon + '.php' : addonData.url,
				}
			);
		},

		/**
		 * Initiate template processing for a new form.
		 *
		 * @since 1.6.8
		 */
		applyTemplateOnRequest: function() {

			var urlParams = new URLSearchParams( window.location.search ),
				templateId = urlParams.get( 'template_id' );

			if (
				urlParams.get( 'view' ) !== 'setup' ||
				urlParams.get( 'form_id' ) ||
				! templateId
			) {
				return;
			}

			el.$panel.find( '.wpforms-template .wpforms-btn[data-template="' + templateId + '"]' ).trigger( 'click' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.Setup.init();
