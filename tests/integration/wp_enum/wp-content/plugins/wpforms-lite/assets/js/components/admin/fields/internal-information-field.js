/* global wpforms_builder, wpf, WPFormsBuilder, WPForms, md5 */

'use strict';

/**
 * WPForms Internal Information Field builder functions.
 *
 * @since 1.7.6
 */
var WPFormsInternalInformationField = window.WPFormsInternalInformationField || ( function( document, window, $ ) { // eslint-disable-line

	/**
	 * WPForms builder element.
	 *
	 * @since 1.7.6
	 *
	 * @type {jQuery}
	 */
	let $builder;

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.6
	 *
	 * @type {object}
	 */
	let app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.6
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Initialized once the DOM is fully loaded.
		 *
		 * @since 1.7.6
		 */
		ready: function() {

			$builder = $( '#wpforms-builder' );

			app.bindUIActionsFields();
		},

		/**
		 * Element bindings.
		 *
		 * @since 1.7.6
		 */
		bindUIActionsFields: function() {

			app.dragDisable();

			$builder
				.on( 'wpformsFieldAdd', app.dragDisable )
				.on( 'input', '.wpforms-field-option-row-heading input[type="text"]', app.headingUpdates )
				.on( 'input', '.wpforms-field-option-row-expanded-description textarea', app.expandedDescriptionUpdates )
				.on( 'input', '.wpforms-field-option-row-cta-label input[type="text"]', app.ctaButtonLabelUpdates )
				.on( 'input', '.wpforms-field-option-row-cta-link input[type="text"]', app.ctaButtonLinkUpdates )
				.on( 'click', '.cta-button.cta-expand-description a', app.showExpandedDescription )
				.on( 'focusout', '.wpforms-field-option-row-cta-link input[type="text"]', app.validateCTAlinkField )
				.on( 'mousedown', '.wpforms-field-internal-information-checkbox', app.handleCheckboxClick )
				.on( 'wpformsDescriptionFieldUpdated', app.descriptionFieldUpdated )
				.on( 'wpformsBeforeFieldDeleteAlert', app.preventDeleteFieldAlert )
				.on( 'mouseenter', '.internal-information-not-editable .wpforms-field-delete', app.showDismissTitle );
		},

		/**
		 * Save checkbox state as a post meta.
		 *
		 * @since 1.7.6
		 *
		 * @param {string} name    Checkbox name.
		 * @param {int}    checked Checkbox state.
		 */
		saveInternalInformationCheckbox: function( name, checked ) {

			$.post(
				wpforms_builder.ajax_url,
				{
					action: 'wpforms_builder_save_internal_information_checkbox',
					formId: $( '#wpforms-builder-form' ).data( 'id' ),
					name: name,
					checked: checked,
					nonce: wpforms_builder.nonce,
				}
			);
		},

		/**
		 * Replace checkboxes.
		 *
		 * @since 1.7.6
		 * @since 1.7.9 Added ID parameter.
		 *
		 * @param {string} description Expanded description.
		 * @param {int}    id          Field ID.
		 *
		 * @returns {string} Expanded description with checkboxes HTML.
		 */
		replaceCheckboxes: function( description, id ) {

			const lines  = description.split( /\r?\n/ ),
				replaced = [],
				needle   = '[] ';

			let lineNumber = -1;

			for ( let line of lines ) {

				lineNumber++;
				line = line.trim();

				if ( ! line.startsWith( needle ) ) {
					replaced.push( line );

					continue;
				}

				const hash = md5( line ),
					name = `iif-${id}-${hash}-${lineNumber}`;

				line = line.replace( '[] ', `<div class="wpforms-field-internal-information-checkbox-wrap"><div class="wpforms-field-internal-information-checkbox-input"><input type="checkbox" name="${name}" value="1" class="wpforms-field-internal-information-checkbox" /></div><div class="wpforms-field-internal-information-checkbox-label">` );				line += '</div></div>';

				replaced.push( line );
			}

			return ( wpf.wpautop( replaced.join( '\n' ) ) ).replace( /<br \/>\n$/, '' );
		},

		/**
		 * Do not allow field to be draggable.
		 *
		 * @since 1.7.9
		 */
		dragDisable: function() {

			WPForms.Admin.Builder.DragFields.fieldDragDisable( $( '.internal-information-not-draggable' ), false );
		},

		/**
		 * Real-time updates for "Heading" field option.
		 *
		 * @since 1.7.6
		 */
		headingUpdates: function() {

			let $this = $( this ),
				value = wpf.sanitizeHTML( $this.val() ),
				$head = $( '#wpforms-field-' + $this.parent().data( 'field-id' ) ).find( '.wpforms-field-internal-information-row-heading .heading' );

			$head.toggle( value.length !== 0 );
			WPFormsBuilder.updateDescription( $head.find( '.text' ), value );
		},

		/**
		 * Real-time updates for "Expanded Description" field option.
		 *
		 * @since 1.7.6
		 */
		expandedDescriptionUpdates: function() {

			const $this          = $( this ),
				value            = wpf.sanitizeHTML( $this.val() ),
				id               = $this.parent().data( 'field-id' ),
				$field           = $( '#wpforms-field-' + id ),
				$wrapper         = $field.find( '.internal-information-wrap' ),
				$buttonContainer = $field.find( '.wpforms-field-internal-information-row-cta-button' ),
				$options         = $( '#wpforms-field-option-' + id ),
				link             = $options.find( '.wpforms-field-option-row-cta-link input[type="text"]' ).val(),
				label            = $options.find( '.wpforms-field-option-row-cta-label input[type="text"]' ).val().length !== 0 ? $options.find( '.wpforms-field-option-row-cta-label input[type="text"]' ).val() : wpforms_builder.empty_label,
				$expandable      = $wrapper.find( '.wpforms-field-internal-information-row-expanded-description' );

			const newLines = app.replaceCheckboxes( value, id );

			WPFormsBuilder.updateDescription( $wrapper.find( '.expanded-description' ), newLines );

			if ( value.length !== 0 ) { // Expanded description has content.
				if ( $expandable.hasClass( 'expanded' ) ) {
					return;
				}

				// Update CTA button.
				$buttonContainer.html( app.notExpandedButton() );

				return;
			}

			$expandable.hide().removeClass( 'expanded' );

			if ( link.length === 0 ) { // Expanded description does not have value and button has no link.
				$buttonContainer.html( '' );

				return;
			}

			$buttonContainer.html( app.standardCtaButton( link, label ) );
		},

		/**
		 * Expand additional description on button click.
		 *
		 * @since 1.7.6
		 *
		 * @param {object} event Click event.
		 */
		showExpandedDescription: function( event ) {

			event.preventDefault();

			const $this          = $( this ),
				id               = $this.closest( '.wpforms-field-internal-information' ).data( 'field-id' ),
				$expandable      = $this.closest( '.internal-information-content' ).find( '.wpforms-field-internal-information-row-expanded-description' ),
				$buttonContainer = $( '#wpforms-field-' + id ).find( '.wpforms-field-internal-information-row-cta-button' ),
				isExpanded       = $expandable.hasClass( 'expanded' );

			$expandable.toggleClass( 'expanded' );

			if ( ! isExpanded ) {
				$expandable.slideDown( 400 );
				$buttonContainer.html( app.expandedButton() );

				return;
			}

			$expandable.slideUp( 400 );
			$buttonContainer.html( app.notExpandedButton() );
		},

		/**
		 * Validate if the CTA Link field has correct url.
		 *
		 * @since 1.7.6
		 */
		validateCTAlinkField: function() {

			const $field = $( this ),
				url      = $field.val().trim();

			$field.val( url );

			if ( url === '' || wpf.isURL( url ) ) {
				return;
			}

			$.confirm(
				{
					title: wpforms_builder.heads_up,
					content: wpforms_builder.iif_redirect_url_field_error,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_builder.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {
								$field.trigger( 'focus' );
							},
						},
					},
				}
			);
		},

		/**
		 * Handle checkbox checking.
		 *
		 * @since 1.7.6
		 *
		 * @param {object} event Click event.
		 */
		handleCheckboxClick: function( event ) {

			event.preventDefault();

			const $this = $( this ),
				checked = ! $this.prop( 'checked' );

			$this.prop( 'checked', checked );

			app.saveInternalInformationCheckbox( $this.prop( 'name' ), Number( checked ) );
		},

		/**
		 * Replace checkboxes on description field.
		 *
		 * @since 1.7.6
		 *
		 * @param {object} event Triggered event.
		 * @param {object} data  Field element and field value.
		 */
		descriptionFieldUpdated: function( event, data ) {

			const type = $( '#wpforms-field-' + data.id ).data( 'field-type' );

			if ( type !== 'internal-information' || data.value.length === 0 ) {
				return;
			}

			data.value = app.replaceCheckboxes( data.value, data.id );

			WPFormsBuilder.updateDescription( data.descField, data.value );
		},

		/**
		 * Prevent delete field alert to show.
		 *
		 * @since 1.7.6
		 *
		 * @param {object} event     Triggered event.
		 * @param {object} fieldData Field data.
		 * @param {string} type      Field type.
		 */
		preventDeleteFieldAlert: function( event, fieldData, type ) {

			if ( type === 'internal-information' ) {
				event.preventDefault();
				WPFormsBuilder.fieldDeleteById( fieldData.id, type, 50 );
			}
		},

		/**
		 * Replace Delete field button title with Dismiss.
		 *
		 * @since 1.7.6
		 */
		showDismissTitle: function() {

			$( this ).attr( 'title', wpforms_builder.iif_dismiss );
		},

		/**
		 * Real-time updates for "CTA button" link.
		 *
		 * @since 1.7.6
		 */
		ctaButtonLinkUpdates() {

			let $this            = $( this ),
				id               = $this.parent().data( 'field-id' ),
				$field           = $( '#wpforms-field-' + id ),
				$buttonContainer = $field.find( '.wpforms-field-internal-information-row-cta-button' ),
				$expandable      = $field.find( '.wpforms-field-internal-information-row-expanded-description' ),
				desc             = $this.closest( '#wpforms-field-option-' + id ).find( '.wpforms-field-option-row-expanded-description textarea' ).val(),
				label            = $this.closest( '#wpforms-field-option-' + id ).find( '.wpforms-field-option-row-cta-label input[type="text"]' ).val();

			if ( desc.length !== 0 ) {

				if ( $expandable.hasClass( 'expanded' ) ) {

					$buttonContainer.html( app.expandedButton() );

					return;
				}
				$buttonContainer.html( app.notExpandedButton() );

				return;
			}

			if ( wpf.isURL( $this.val() ) && label.length !== 0 ) {
				$buttonContainer.html( app.standardCtaButton( $this.val(), label ) );

				return;
			}

			$buttonContainer.html( '' );
		},

		/**
		 * Real-time updates for "CTA button" label.
		 *
		 * @since 1.7.6
		 */
		ctaButtonLabelUpdates: function() {

			let $this            = $( this ),
				value            = wpf.sanitizeHTML( $this.val() ),
				id               = $this.parent().data( 'field-id' ),
				$field           = $( '#wpforms-field-' + id ),
				$buttonContainer = $field.find( '.wpforms-field-internal-information-row-cta-button' ),
				$expandable      = $field.find( '.wpforms-field-internal-information-row-expanded-description' ),
				desc             = $this.closest( '#wpforms-field-option-' + id ).find( '.wpforms-field-option-row-expanded-description textarea' ).val(),
				link             = $this.closest( '#wpforms-field-option-' + id ).find( '.wpforms-field-option-row-cta-link input[type="text"]' ).val();

			if ( desc.length !== 0 && value.length !== 0 ) {
				if ( $expandable.hasClass( 'expanded' ) ) {

					$buttonContainer.html( app.expandedButton() );

					return;
				}

				$buttonContainer.html( app.notExpandedButton() );

				return;
			}

			if ( value.length !== 0 && wpf.isURL( link ) ) {
				$buttonContainer.html( app.standardCtaButton( link, value ) );

				return;
			}

			if ( desc.length === 0 ) {
				$buttonContainer.html( '' );
			}
		},

		/**
		 * Standard CTA button template.
		 *
		 * @since 1.7.6
		 *
		 * @param {string} url   Button URL.
		 * @param {string} label Button label.
		 *
		 * @returns {string} Button HTML.
		 */
		standardCtaButton: function( url, label ) {

			let button = `<div class="cta-button cta-link-external ">
				<a href="%url%" target="_blank" rel="noopener noreferrer">
					<span class="button-label">%label%</span>
				</a></div>`;

			return button.replace( '%url%', wpf.sanitizeHTML( url ) ).replace( '%label%', wpf.sanitizeHTML( label ) );
		},

		/**
		 * Not expanded button.
		 *
		 * @since 1.7.6
		 *
		 * @returns {string} Not expanded button HTML.
		 */
		notExpandedButton: function() {

			let button = `<div class="cta-button cta-expand-description not-expanded">
				<a href="#" target="_blank" rel="noopener noreferrer">
					<span class="button-label">%label%</span>
					<span class="icon not-expanded">
						<svg viewBox="0 0 10 7">
							<path d="M4.91016 5.90234C5.15625 6.14844 5.56641 6.14844 5.8125 5.90234L9.53125 2.18359C9.80469 1.91016 9.80469 1.5 9.53125 1.25391L8.92969 0.625C8.65625 0.378906 8.24609 0.378906 8 0.625L5.34766 3.27734L2.72266 0.625C2.47656 0.378906 2.06641 0.378906 1.79297 0.625L1.19141 1.25391C0.917969 1.5 0.917969 1.91016 1.19141 2.18359L4.91016 5.90234Z"></path>
							<path d="M4.91016 5.90234C5.15625 6.14844 5.56641 6.14844 5.8125 5.90234L9.53125 2.18359C9.80469 1.91016 9.80469 1.5 9.53125 1.25391L8.92969 0.625C8.65625 0.378906 8.24609 0.378906 8 0.625L5.34766 3.27734L2.72266 0.625C2.47656 0.378906 2.06641 0.378906 1.79297 0.625L1.19141 1.25391C0.917969 1.5 0.917969 1.91016 1.19141 2.18359L4.91016 5.90234Z"></path>
						</svg>
					</span>
				</a></div>`;

			return button.replace( '%label%', wpforms_builder.iif_more );
		},

		/**
		 * Expanded button.
		 *
		 * @since 1.7.6
		 *
		 * @returns {string} Expanded button HTML.
		 */
		expandedButton: function() {

			let button = `<div class="cta-button cta-expand-description expanded">
				<a href="#" target="_blank" rel="noopener noreferrer">
					<span class="button-label">%label%</span>
					<span class="icon expanded">
						<svg viewBox="0 0 10 7">
							<path d="M5.83984 0.625C5.56641 0.378906 5.15625 0.378906 4.91016 0.625L1.19141 4.34375C0.917969 4.61719 0.917969 5.02734 1.19141 5.27344L1.79297 5.90234C2.06641 6.14844 2.47656 6.14844 2.72266 5.90234L5.375 3.25L8 5.90234C8.24609 6.14844 8.68359 6.14844 8.92969 5.90234L9.55859 5.27344C9.80469 5.02734 9.80469 4.61719 9.55859 4.34375L5.83984 0.625Z" fill="red"></path>
						</svg>
					</span>
				</a></div>`;

			return button.replace( '%label%', wpforms_builder.close );
		},
	};

	return app;
}( document, window, jQuery ) );

WPFormsInternalInformationField.init();
