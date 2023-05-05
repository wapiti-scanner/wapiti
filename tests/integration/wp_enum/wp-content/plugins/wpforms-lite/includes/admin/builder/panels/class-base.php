<?php

/**
 * Base panel class.
 *
 * @since 1.0.0
 */
abstract class WPForms_Builder_Panel {

	/**
	 * Full name of the panel.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $name;

	/**
	 * Slug.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $slug;

	/**
	 * Font Awesome Icon used for the editor button, eg "fa-list".
	 *
	 * @since 1.0.0
	 *
	 * @var mixed
	 */
	public $icon = false;

	/**
	 * Priority order the field button should show inside the "Add Fields" tab.
	 *
	 * @since 1.0.0
	 *
	 * @var int
	 */
	public $order = 50;

	/**
	 * If panel contains a sidebar element or is full width.
	 *
	 * @since 1.0.0
	 *
	 * @var bool
	 */
	public $sidebar = false;

	/**
	 * Contain form object if we have one.
	 *
	 * @since 1.0.0
	 *
	 * @var object
	 */
	public $form;

	/**
	 * Contain array of the form data (post_content).
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	public $form_data;

	/**
	 * Class instance.
	 *
	 * @since 1.7.7
	 *
	 * @var static
	 */
	private static $instance;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		// Load form if found.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$form_id    = isset( $_GET['form_id'] ) ? absint( $_GET['form_id'] ) : false;
		$this->form = wpforms()->get( 'form' )->get( $form_id );

		$this->form_data = $this->form ? wpforms_decode( $this->form->post_content ) : false;

		// Get current revision, if available.
		$revision = wpforms()->get( 'revisions' )->get_revision();

		// If we're viewing a valid revision, replace the form data so the Form Builder shows correct state.
		if ( $revision && isset( $revision->post_content ) ) {
			$this->form_data = wpforms_decode( $revision->post_content );
		}

		// Bootstrap.
		$this->init();

		// Load panel specific enqueues.
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ], 15 );

		// Primary panel button.
		add_action( 'wpforms_builder_panel_buttons', [ $this, 'button' ], $this->order, 2 );

		// Output.
		add_action( 'wpforms_builder_panels', [ $this, 'panel_output' ], $this->order, 2 );

		// Save instance.
		self::$instance = $this;
	}

	/**
	 * Get class instance.
	 *
	 * @since 1.7.7
	 *
	 * @return static
	 */
	public static function instance() {

		if ( self::$instance === null || ! self::$instance instanceof static ) {
			self::$instance = new static();
		}

		return self::$instance;
	}

	/**
	 * All systems go. Used by children.
	 *
	 * @since 1.0.0
	 */
	public function init() {
	}

	/**
	 * Enqueue assets for the builder. Used by children.
	 *
	 * @since 1.0.0
	 */
	public function enqueues() {
	}

	/**
	 * Primary panel button in the left panel navigation.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $form
	 * @param string $view
	 */
	public function button( $form, $view ) {

		$active = $view === $this->slug ? 'active' : '';
		?>

		<button class="wpforms-panel-<?php echo esc_attr( $this->slug ); ?>-button <?php echo $active; ?>" data-panel="<?php echo esc_attr( $this->slug ); ?>">
			<i class="fa <?php echo esc_attr( $this->icon ); ?>"></i>
			<span><?php echo esc_html( $this->name ); ?></span>
		</button>

		<?php
	}

	/**
	 * Output the contents of the panel.
	 *
	 * @since 1.0.0
	 *
	 * @param object $form Current form object.
	 * @param string $view Active Form Builder view (panel).
	 */
	public function panel_output( $form, $view ) {

		$wrap    = $this->sidebar ? 'wpforms-panel-sidebar-content' : 'wpforms-panel-full-content';
		$classes = [ 'wpforms-panel' ];

		if ( in_array( $this->slug, [ 'fields', 'revisions' ], true ) ) {
			$classes[] = 'wpforms-panel-fields';
		}

		if ( $view === $this->slug ) {
			$classes[] = 'active';
		}

		printf( '<div class="%s" id="wpforms-panel-%s">', wpforms_sanitize_classes( $classes, true ), esc_attr( $this->slug ) );

		printf( '<div class="%s">', $wrap );

		if ( true === $this->sidebar ) {

			if ( $this->slug === 'fields' ) {
				echo '<div class="wpforms-panel-sidebar-toggle"><div class="wpforms-panel-sidebar-toggle-vertical-line"></div><div class="wpforms-panel-sidebar-toggle-icon"><i class="fa fa-angle-left"></i></div></div>';
			}

			echo '<div class="wpforms-panel-sidebar">';

			do_action( 'wpforms_builder_before_panel_sidebar', $this->form, $this->slug );

			$this->panel_sidebar();

			do_action( 'wpforms_builder_after_panel_sidebar', $this->form, $this->slug );

			echo '</div>';

		}

		echo '<div class="wpforms-panel-content-wrap">';

		echo '<div class="wpforms-panel-content">';

		do_action( 'wpforms_builder_before_panel_content', $this->form, $this->slug );

		$this->panel_content();

		do_action( 'wpforms_builder_after_panel_content', $this->form, $this->slug );

		echo '</div>';

		echo '</div>';

		echo '</div>';

		echo '</div>';
	}

	/**
	 * Output the panel's sidebar if we have one.
	 *
	 * @since 1.0.0
	 */
	public function panel_sidebar() {
	}

	/**
	 * Output panel sidebar sections.
	 *
	 * @since 1.0.0
	 *
	 * @param string $name Sidebar section name.
	 * @param string $slug Sidebar section slug.
	 * @param string $icon Sidebar section icon.
	 */
	public function panel_sidebar_section( $name, $slug, $icon = '' ) {

		$default_classes = [
			'wpforms-panel-sidebar-section',
			'wpforms-panel-sidebar-section-' . $slug,
		];

		if ( $slug === 'default' ) {
			$default_classes[] = 'default';
		}

		if ( ! empty( $icon ) ) {
			$default_classes[] = 'icon';
		}

		/**
		 * Allow adding custom CSS classes to a sidebar section in the Form Builder.
		 *
		 * @since 1.7.7.2
		 *
		 * @param array  $classes Sidebar section classes.
		 * @param string $name    Sidebar section name.
		 * @param string $slug    Sidebar section slug.
		 * @param string $icon    Sidebar section icon.
		 */
		$classes = (array) apply_filters( 'wpforms_builder_panel_sidebar_section_classes', [], $name, $slug, $icon );
		$classes = array_merge( $default_classes, $classes );

		echo '<a href="#" class="' . wpforms_sanitize_classes( $classes, true ) . '" data-section="' . esc_attr( $slug ) . '">';

		if ( ! empty( $icon ) ) {
			echo '<img src="' . esc_url( $icon ) . '">';
		}

		echo esc_html( $name );

		echo '<i class="fa fa-angle-right wpforms-toggle-arrow"></i>';

		echo '</a>';
	}

	/**
	 * Output the panel's primary content.
	 *
	 * @since 1.0.0
	 */
	public function panel_content() {
	}
}
