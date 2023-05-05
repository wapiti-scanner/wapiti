/* global wpforms_builder_settings, Choices, wpf */

/**
 * Form Builder Settings Panel module.
 *
 * @since 1.7.5
 */

'use strict';

var WPForms = window.WPForms || {};

WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.Settings = WPForms.Admin.Builder.Settings || ( function( document, window, $ ) {

	/**
	 * Elements holder.
	 *
	 * @since 1.7.5
	 *
	 * @type {object}
	 */
	var el = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.7.5
	 *
	 * @type {object}
	 */
	var vars = {};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.5
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.5
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * DOM is fully loaded.
		 *
		 * @since 1.7.5
		 */
		ready: function() {

			app.setup();
			app.initTags();
			app.events();
		},

		/**
		 * Setup. Prepare some variables.
		 *
		 * @since 1.7.5
		 */
		setup: function() {

			// Cache DOM elements.
			el = {
				$builder:    $( '#wpforms-builder' ),
				$panel:      $( '#wpforms-panel-settings' ),
				$selectTags: $( '#wpforms-panel-field-settings-form_tags' ),
			};
		},

		/**
		 * Bind events.
		 *
		 * @since 1.7.5
		 */
		events: function() {

			el.$panel
				.on( 'keydown', '#wpforms-panel-field-settings-form_tags-wrap input', app.addCustomTagInput )
				.on( 'removeItem', '#wpforms-panel-field-settings-form_tags-wrap select', app.editTagsRemoveItem );

			el.$selectTags
				.on( 'change', app.changeTags );
		},

		/**
		 * Init Choices.js on the Tags select input element.
		 *
		 * @since 1.7.5
		 */
		initTags: function() {

			// Skip in certain cases.
			if (
				! el.$selectTags.length ||
				typeof window.Choices !== 'function'
			) {
				return;
			}

			// Init Choices.js object instance.
			vars.tagsChoicesObj = new Choices( el.$selectTags[0], wpforms_builder_settings.choicesjs_config );

			// Backup current value.
			var	currentValue = vars.tagsChoicesObj.getValue( true );

			// Update all tags choices.
			vars.tagsChoicesObj
				.clearStore()
				.setChoices(
					wpforms_builder_settings.all_tags_choices,
					'value',
					'label',
					true
				)
				.setChoiceByValue( currentValue );

			el.$selectTags.data( 'choicesjs', vars.tagsChoicesObj );

			app.initTagsHiddenInput();
		},

		/**
		 * Init Tags hidden input element.
		 *
		 * @since 1.7.5
		 */
		initTagsHiddenInput: function() {

			// Create additional hidden input.
			el.$selectTagsHiddenInput = $( '<input type="hidden" name="settings[form_tags_json]">' );
			el.$selectTags
				.closest( '.wpforms-panel-field' )
				.append( el.$selectTagsHiddenInput );

			// Update hidden input value.
			app.changeTags( null );

			// Update form state when hidden input initialized.
			// This will prevent a please-save-prompt to appear, when switching from revisions without doing any changes anywhere.
			if ( wpf.initialSave === true ) {
				wpf.savedState = wpf.getFormState( '#wpforms-builder-form' );
			}
		},

		/**
		 * Add custom item to Tags dropdown on input.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		addCustomTagInput: function( event ) {

			if ( [ 'Enter', ',' ].indexOf( event.key ) < 0 ) {
				return;
			}

			event.preventDefault();
			event.stopPropagation();

			if ( ! vars.tagsChoicesObj || event.target.value.length === 0 ) {
				return;
			}

			var	tagLabel = _.escape( event.target.value ).trim(),
				labels = _.map( vars.tagsChoicesObj.getValue(), 'label' ).map( function( label ) {
					return label.toLowerCase().trim();
				} );

			if ( tagLabel === '' || labels.indexOf( tagLabel.toLowerCase() ) >= 0 ) {
				vars.tagsChoicesObj.clearInput();

				return;
			}

			app.addCustomTagInputCreate( tagLabel );
			app.changeTags( event );
		},

		/**
		 * Remove tag from Tags field event handler.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		editTagsRemoveItem: function( event ) {

			var	allValues = _.map( wpforms_builder_settings.all_tags_choices, 'value' );

			if ( allValues.indexOf( event.detail.value ) >= 0 ) {
				return;
			}

			// We should remove new tag from the list of choices.
			var choicesObj = $( event.target ).data( 'choicesjs' ),
				currentValue = choicesObj.getValue( true ),
				choices = _.filter( choicesObj._currentState.choices, function( item ) {
					return item.value !== event.detail.value;
				} );

			choicesObj
				.clearStore()
				.setChoices( choices, 'value', 'label', true )
				.setChoiceByValue( currentValue );
		},

		/**
		 * Add custom item to Tags dropdown on input (second part).
		 *
		 * @since 1.7.5
		 *
		 * @param {object} tagLabel Event object.
		 */
		addCustomTagInputCreate: function( tagLabel ) {

			var tag = _.find( wpforms_builder_settings.all_tags_choices, { label: tagLabel } );

			if ( tag && tag.value ) {
				vars.tagsChoicesObj.setChoiceByValue( tag.value );
			} else {
				vars.tagsChoicesObj.setChoices(
					[
						{
							value: tagLabel,
							label: tagLabel,
							selected: true,
						},
					],
					'value',
					'label',
					false
				);
			}

			vars.tagsChoicesObj.clearInput();
		},

		/**
		 * Change Tags field event handler.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		changeTags: function( event ) {

			var tagsValue = vars.tagsChoicesObj.getValue(),
				tags = [];

			for ( var i = 0; i < tagsValue.length; i++ ) {
				tags.push( {
					value: tagsValue[ i ].value,
					label: tagsValue[ i ].label,
				} );
			}

			// Update Tags field hidden input value.
			el.$selectTagsHiddenInput.val(
				JSON.stringify( tags )
			);
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.Settings.init();
