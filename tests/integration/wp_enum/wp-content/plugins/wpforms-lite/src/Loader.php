<?php

namespace WPForms;

/**
 * WPForms Class Loader.
 *
 * @since 1.5.8
 */
class Loader {

	/**
	 * Classes to register.
	 *
	 * @since 1.5.8
	 *
	 * @var array
	 */
	private $classes = [];

	/**
	 * Loader init.
	 *
	 * @since 1.5.8
	 */
	public function init() {

		$this->populate_classes();

		wpforms()->register_bulk( $this->classes );
	}

	/**
	 * Populate the classes to register.
	 *
	 * @since 1.5.8
	 */
	protected function populate_classes() {

		$this->populate_frontend();
		$this->populate_admin();
		$this->populate_forms_overview();
		$this->populate_builder();
		$this->populate_migrations();
		$this->populate_capabilities();
		$this->populate_tasks();
		$this->populate_forms();
		$this->populate_smart_tags();
		$this->populate_logger();
		$this->populate_education();
		$this->populate_robots();
		$this->populate_anti_spam_filters();
	}

	/**
	 * Populate the Forms related classes.
	 *
	 * @since 1.6.2
	 */
	private function populate_forms() {

		$this->classes[] = [
			'name' => 'Forms\Preview',
			'id'   => 'preview',
		];

		$this->classes[] = [
			'name' => 'Forms\Token',
			'id'   => 'token',
		];

		$this->classes[] = [
			'name' => 'Forms\Honeypot',
			'id'   => 'honeypot',
		];

		$this->classes[] = [
			'name' => 'Forms\Akismet',
			'id'   => 'akismet',
		];

		$this->classes[] = [
			'name' => 'Forms\Submission',
			'id'   => 'submission',
			'hook' => false,
			'run'  => false,
		];

		$this->classes[] = [
			'name' => 'Forms\Locator',
			'id'   => 'locator',
		];

		$this->classes[] = [
			'name' => 'Forms\IconChoices',
			'id'   => 'icon_choices',
		];
	}

	/**
	 * Populate Frontend related classes.
	 *
	 * @since 1.8.1
	 */
	private function populate_frontend() {

		$this->classes[] = [
			'name' => 'Frontend\Amp',
			'id'   => 'amp',
		];

		$this->classes[] = [
			'name' => 'Frontend\Captcha',
			'id'   => 'captcha',
		];

		$this->classes[] = [
			'name' => 'Frontend\CSSVars',
			'id'   => 'css_vars',
		];

		$this->classes[] = [
			'name' => 'Frontend\Classic',
			'id'   => 'frontend_classic',
		];

		$this->classes[] = [
			'name' => 'Frontend\Modern',
			'id'   => 'frontend_modern',
		];

		$this->classes[] = [
			'name' => 'Frontend\Frontend',
			'id'   => 'frontend',
		];
	}

	/**
	 * Populate Admin related classes.
	 *
	 * @since 1.6.0
	 */
	private function populate_admin() {

		array_push(
			$this->classes,
			[
				'name' => 'Admin\Notice',
				'id'   => 'notice',
			],
			[
				'name' => 'Admin\Revisions',
				'id'   => 'revisions',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Addons\AddonsCache',
				'id'   => 'addons_cache',
			],
			[
				'name' => 'Admin\Addons\Addons',
				'id'   => 'addons',
			],
			[
				'name' => 'Admin\AdminBarMenu',
				'hook' => 'init',
			],
			[
				'name' => 'Admin\Notifications\Notifications',
				'id'   => 'notifications',
			],
			[
				'name' => 'Admin\Notifications\EventDriven',
			],
			[
				'name' => 'Admin\Entries\Edit',
				'id'   => 'entries_edit',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Pages\Templates',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Entries\Export\Export',
			],
			[
				'name' => 'Admin\Challenge',
				'id'   => 'challenge',
			],
			[
				'name' => 'Admin\FormEmbedWizard',
				'hook' => 'admin_init',
				'id'   => 'form_embed_wizard',
			],
			[
				'name' => 'Admin\SiteHealth',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Settings\ModernMarkup',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Settings\Captcha\Page',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Admin\Tools\Tools',
				'hook' => 'current_screen',
			],
			[
				'name'      => 'Admin\Tools\Importers',
				'hook'      => 'admin_init',
				'run'       => 'load',
				'condition' => wp_doing_ajax(),
			],
			[
				'name' => 'Admin\Pages\Addons',
				'id'   => 'addons_page',
			],
			[
				'name' => 'Admin\Pages\ConstantContact',
				'hook' => 'admin_init',
			],
			[
				'name' => 'Forms\Fields\Richtext\EntryViewContent',
			]
		);
	}

	/**
	 * Populate Forms Overview admin page related classes.
	 *
	 * @since 1.7.5
	 */
	private function populate_forms_overview() {

		if ( ! wpforms_is_admin_page( 'overview' ) && ! wp_doing_ajax() ) {
			return;
		}

		array_push(
			$this->classes,
			[
				'name' => 'Admin\Forms\Ajax\Tags',
				'id'   => 'forms_tags_ajax',
			],
			[
				'name' => 'Admin\Forms\Search',
				'id'   => 'forms_search',
			],
			[
				'name' => 'Admin\Forms\Views',
				'id'   => 'forms_views',
			],
			[
				'name' => 'Admin\Forms\BulkActions',
				'id'   => 'forms_bulk_actions',
			],
			[
				'name' => 'Admin\Forms\Tags',
				'id'   => 'forms_tags',
			]
		);
	}

	/**
	 * Populate Form Builder related classes.
	 *
	 * @since 1.6.8
	 */
	private function populate_builder() {

		array_push(
			$this->classes,
			[
				'name' => 'Admin\Builder\Help',
				'id'   => 'builder_help',
			],
			[
				'name' => 'Admin\Builder\Shortcuts',
			],
			[
				'name' => 'Admin\Builder\TemplatesCache',
				'id'   => 'builder_templates_cache',
			],
			[
				'name' => 'Admin\Builder\TemplateSingleCache',
				'id'   => 'builder_template_single',
			],
			[
				'name' => 'Admin\Builder\Templates',
				'id'   => 'builder_templates',
			],
			[
				'name' => 'Admin\Builder\AntiSpam',
				'hook' => 'wpforms_builder_init',
			],
			[
				'name' => 'Admin\Builder\Notifications\Advanced\Settings',
			],
			[
				'name' => 'Admin\Builder\Notifications\Advanced\FileUploadAttachment',
			],
			[
				'name' => 'Admin\Builder\Notifications\Advanced\EntryCsvAttachment',
			]
		);
	}

	/**
	 * Populate migration classes.
	 *
	 * @since 1.5.9
	 */
	private function populate_migrations() {

		$this->classes[] = [
			'name' => 'Migrations\Migrations',
			'hook' => 'plugins_loaded',
		];
	}

	/**
	 * Populate access management (capabilities) classes.
	 *
	 * @since 1.5.8
	 */
	private function populate_capabilities() {

		array_push(
			$this->classes,
			[
				'name' => 'Access\Capabilities',
				'id'   => 'access',
				'hook' => 'plugins_loaded',
			],
			[
				'name' => 'Access\Integrations',
			],
			[
				'name'      => 'Admin\Settings\Access',
				'condition' => is_admin(),
			]
		);
	}

	/**
	 * Populate tasks related classes.
	 *
	 * @since 1.5.9
	 */
	private function populate_tasks() {

		array_push(
			$this->classes,
			[
				'name' => 'Tasks\Tasks',
				'id'   => 'tasks',
				'hook' => 'init',
			],
			[
				'name' => 'Tasks\Meta',
				'id'   => 'tasks_meta',
				'hook' => false,
				'run'  => false,
			]
		);
	}

	/**
	 * Populate smart tags loaded classes.
	 *
	 * @since 1.6.7
	 */
	private function populate_smart_tags() {

		array_push(
			$this->classes,
			[
				'name' => 'SmartTags\SmartTags',
				'id'   => 'smart_tags',
				'run'  => 'hooks',
			]
		);
	}

	/**
	 * Populate logger loaded classes.
	 *
	 * @since 1.6.3
	 */
	private function populate_logger() {

		array_push(
			$this->classes,
			[
				'name' => 'Logger\Log',
				'id'   => 'log',
				'hook' => false,
				'run'  => 'hooks',
			]
		);
	}

	/**
	 * Populate education related classes.
	 *
	 * @since 1.6.6
	 */
	private function populate_education() {

		// Kill switch.
		if ( ! (bool) apply_filters( 'wpforms_admin_education', true ) ) {
			return;
		}

		// Education core classes.
		array_push(
			$this->classes,
			[
				'name' => 'Admin\Education\Core',
				'id'   => 'education',
			],
			[
				'name' => 'Admin\Education\Fields',
				'id'   => 'education_fields',
			],
			[
				'name' => 'Admin\Education\Admin\Settings\SMTP',
				'id'   => 'education_smtp_notice',
			],
			[
				'name' => 'Admin\Education\Admin\EditPost',
				'hook' => 'load-edit.php',
			],
			[
				'name' => 'Admin\Education\Admin\EditPost',
				'hook' => 'load-post-new.php',
			],
			[
				'name' => 'Admin\Education\Admin\EditPost',
				'hook' => 'load-post.php',
			]
		);

		// Education features classes.
		$features = [
			'LiteConnect',
			'Builder\Captcha',
			'Builder\Fields',
			'Builder\Settings',
			'Builder\Providers',
			'Builder\Payments',
			'Builder\DidYouKnow',
			'Builder\Geolocation',
			'Builder\Confirmations',
			'Builder\Notifications',
			'Admin\DidYouKnow',
			'Admin\Settings\Integrations',
			'Admin\Settings\Geolocation',
			'Admin\NoticeBar',
			'Admin\Entries\Geolocation',
			'Admin\Entries\UserJourney',
		];

		foreach ( $features as $feature ) {
			$this->classes[] = [
				'name' => 'Admin\Education\\' . $feature,
			];
		}
	}

	/**
	 * Populate robots loaded class.
	 *
	 * @since 1.7.0
	 */
	private function populate_robots() {

		$this->classes[] = [
			'name' => 'Robots',
			'run'  => 'hooks',
		];
	}

	/**
	 * Populate Country and Keyword filters from AntiSpam settings.
	 *
	 * @since 1.7.8
	 */
	private function populate_anti_spam_filters() {

		array_push(
			$this->classes,
			[
				'name' => 'AntiSpam\CountryFilter',
				'hook' => 'init',
			],
			[
				'name' => 'AntiSpam\KeywordFilter',
				'hook' => 'init',
			]
		);
	}
}
