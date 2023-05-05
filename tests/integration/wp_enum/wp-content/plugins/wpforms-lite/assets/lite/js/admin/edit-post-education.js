/* global wpforms_edit_post_education */

/**
 * WPForms Edit Post Education function.
 *
 * @since 1.8.1
 */

'use strict';

const WPFormsEditPostEducation = window.WPFormsEditPostEducation || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.8.1
	 *
	 * @type {object}
	 */
	const app = {

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
		init: function() {

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
		 * Page load.
		 *
		 * @since 1.8.1
		 */
		load: function() {

			if ( ! app.isGutenbergEditor() ) {
				app.maybeShowClassicNotice();
				app.bindClassicEvents();

				return;
			}

			const blockLoadedInterval = setInterval( function() {

				if ( ! document.querySelector( '.editor-post-title__input, iframe[name="editor-canvas"]' ) ) {
					return;
				}

				clearInterval( blockLoadedInterval );

				if ( ! app.isFse() ) {

					app.maybeShowGutenbergNotice();
					app.bindGutenbergEvents();

					return;
				}

				const iframe = document.querySelector( 'iframe[name="editor-canvas"]' );
				const observer = new MutationObserver( function() {

					const iframeDocument = iframe.contentDocument || iframe.contentWindow.document || {};

					if ( iframeDocument.readyState === 'complete' && iframeDocument.querySelector( '.editor-post-title__input' ) ) {
						app.maybeShowGutenbergNotice();
						app.bindFseEvents();

						observer.disconnect();
					}
				} );
				observer.observe( document.body, { subtree: true, childList: true } );
			}, 200 );
		},

		/**
		 * Bind events for Classic Editor.
		 *
		 * @since 1.8.1
		 */
		bindClassicEvents: function() {

			const $document = $( document );

			if ( ! app.isNoticeVisible ) {
				$document.on( 'input', '#title', app.maybeShowClassicNotice );
			}

			$document.on( 'click', '.wpforms-edit-post-education-notice-close', app.closeNotice );
		},

		/**
		 * Bind events for Gutenberg Editor.
		 *
		 * @since 1.8.1
		 */
		bindGutenbergEvents: function() {

			const $document = $( document );

			$document
				.on( 'DOMSubtreeModified', '.edit-post-layout', app.distractionFreeModeToggle );

			if ( app.isNoticeVisible ) {
				return;
			}

			$document
				.on( 'input', '.editor-post-title__input', app.maybeShowGutenbergNotice )
				.on( 'DOMSubtreeModified', '.editor-post-title__input', app.maybeShowGutenbergNotice );
		},

		/**
		 * Bind events for Gutenberg Editor in FSE mode.
		 *
		 * @since 1.8.1
		 */
		bindFseEvents: function() {

			const $iframe = $( 'iframe[name="editor-canvas"]' );

			$( document )
				.on( 'DOMSubtreeModified', '.edit-post-layout', app.distractionFreeModeToggle );

			$iframe.contents()
				.on( 'DOMSubtreeModified', '.editor-post-title__input', app.maybeShowGutenbergNotice );
		},

		/**
		 * Determine if the editor is Gutenberg.
		 *
		 * @since 1.8.1
		 *
		 * @returns {boolean} True if the editor is Gutenberg.
		 */
		isGutenbergEditor: function() {

			return typeof wp !== 'undefined' && typeof wp.blocks !== 'undefined';
		},

		/**
		 * Determine if the editor is Gutenberg in FSE mode.
		 *
		 * @since 1.8.1
		 *
		 * @returns {boolean} True if the Gutenberg editor in FSE mode.
		 */
		isFse: function() {

			return Boolean( $( 'iframe[name="editor-canvas"]' ).length );
		},

		/**
		 * Create a notice for Gutenberg.
		 *
		 * @since 1.8.1
		 */
		showGutenbergNotice: function() {

			wp.data.dispatch( 'core/notices' ).createInfoNotice(
				wpforms_edit_post_education.gutenberg_notice.template,
				app.getGutenbergNoticeSettings()
			);

			// The notice component doesn't have a way to add HTML id or class to the notice.
			// Also, the notice became visible with a delay on old Gutenberg versions.
			const hasNotice = setInterval( function() {

				const noticeBody = $( '.wpforms-edit-post-education-notice-body' );
				if ( ! noticeBody.length ) {
					return;
				}

				const $notice = noticeBody.closest( '.components-notice' );
				$notice.addClass( 'wpforms-edit-post-education-notice' );
				$notice.find( '.is-secondary, .is-link' ).removeClass( 'is-secondary' ).removeClass( 'is-link' ).addClass( 'is-primary' );

				clearInterval( hasNotice );
			}, 100 );
		},

		/**
		 * Get settings for the Gutenberg notice.
		 *
		 * @since 1.8.1
		 *
		 * @returns {object} Notice settings.
		 */
		getGutenbergNoticeSettings: function() {

			const pluginName = 'wpforms-edit-post-product-education-guide';
			const noticeSettings = {
				id: pluginName,
				isDismissible: true,
				HTML: true,
				__unstableHTML: true,
				actions: [
					{
						className: 'wpforms-edit-post-education-notice-guide-button',
						variant: 'primary',
						label: wpforms_edit_post_education.gutenberg_notice.button,
					},
				],
			};

			if ( ! wpforms_edit_post_education.gutenberg_guide ) {

				noticeSettings.actions[0].url = wpforms_edit_post_education.gutenberg_notice.url;

				return noticeSettings;
			}

			const Guide = wp.components.Guide;
			const useState = wp.element.useState;
			const registerPlugin = wp.plugins.registerPlugin;
			const unregisterPlugin = wp.plugins.unregisterPlugin;
			const GutenbergTutorial = function() {

				const [ isOpen, setIsOpen ] = useState( true );

				if ( ! isOpen ) {
					return null;
				}

				return (
					// eslint-disable-next-line react/react-in-jsx-scope
					<Guide
						className="edit-post-welcome-guide"
						onFinish={ () => {
							unregisterPlugin( pluginName );
							setIsOpen( false );
						} }
						pages={ app.getGuidePages() }
					/>
				);
			};

			noticeSettings.onDismiss = app.updateUserMeta;
			noticeSettings.actions[0].onClick = () => registerPlugin( pluginName, { render: GutenbergTutorial } );

			return noticeSettings;
		},

		/**
		 * Get Guide pages in proper format.
		 *
		 * @since 1.8.1
		 *
		 * @returns {Array} Guide Pages.
		 */
		getGuidePages: function() {

			const pages = [];

			wpforms_edit_post_education.gutenberg_guide.forEach( function( page ) {
				pages.push(
					{
						/* eslint-disable react/react-in-jsx-scope */
						content: (
							<>
								<h1 className="edit-post-welcome-guide__heading">{ page.title }</h1>
								<p className="edit-post-welcome-guide__text">{ page.content }</p>
							</>
						),
						image: <img className="edit-post-welcome-guide__image" src={ page.image } alt={ page.title } />,
						/* eslint-enable react/react-in-jsx-scope */
					}
				);
			} );

			return pages;
		},

		/**
		 * Show notice if the page title matches some keywords for Classic Editor.
		 *
		 * @since 1.8.1
		 */
		maybeShowClassicNotice: function() {

			if ( app.isNoticeVisible ) {
				return;
			}

			if ( app.isTitleMatchKeywords( $( '#title' ).val() ) ) {
				app.isNoticeVisible = true;

				$( '.wpforms-edit-post-education-notice' ).removeClass( 'wpforms-hidden' );
			}
		},

		/**
		 * Show notice if the page title matches some keywords for Gutenberg Editor.
		 *
		 * @since 1.8.1
		 */
		maybeShowGutenbergNotice: function() {

			if ( app.isNoticeVisible ) {
				return;
			}

			const $postTitle = app.isFse() ?
				$( 'iframe[name="editor-canvas"]' ).contents().find( '.editor-post-title__input' ) :
				$( '.editor-post-title__input' );
			const tagName = $postTitle.prop( 'tagName' );
			const title = tagName === 'TEXTAREA' ? $postTitle.val() : $postTitle.text();

			if ( app.isTitleMatchKeywords( title ) ) {
				app.isNoticeVisible = true;

				app.showGutenbergNotice();
			}
		},

		/**
		 * Add notice class when the distraction mode is enabled.
		 *
		 * @since 1.8.1.2
		 */
		distractionFreeModeToggle: function() {

			if ( ! app.isNoticeVisible ) {
				return;
			}

			const $document = $( document );
			const isDistractionFreeMode = Boolean( $document.find( '.is-distraction-free' ).length );

			if ( ! isDistractionFreeMode ) {
				return;
			}

			const isNoticeHasClass = Boolean( $( '.wpforms-edit-post-education-notice' ).length );

			if ( isNoticeHasClass ) {
				return;
			}

			const $noticeBody = $document.find( '.wpforms-edit-post-education-notice-body' );
			const $notice = $noticeBody.closest( '.components-notice' );

			$notice.addClass( 'wpforms-edit-post-education-notice' );
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
		isTitleMatchKeywords: function( titleValue ) {

			const expectedTitleRegex = new RegExp( /\b(contact|form)\b/i );

			return expectedTitleRegex.test( titleValue );
		},

		/**
		 * Close a notice.
		 *
		 * @since 1.8.1
		 */
		closeNotice: function() {

			$( this ).closest( '.wpforms-edit-post-education-notice' ).remove();

			app.updateUserMeta();
		},

		/**
		 * Update user meta and don't show the notice next time.
		 *
		 * @since 1.8.1
		 */
		updateUserMeta() {

			$.post(
				wpforms_edit_post_education.ajax_url,
				{
					action: 'wpforms_education_dismiss',
					nonce: wpforms_edit_post_education.education_nonce,
					section: 'edit-post-notice',
				}
			);
		},
	};

	return app;

}( document, window, jQuery ) );

WPFormsEditPostEducation.init();
