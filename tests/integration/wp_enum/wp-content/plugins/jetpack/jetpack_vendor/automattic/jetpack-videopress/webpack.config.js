const path = require( 'path' );
const jetpackWebpackConfig = require( '@automattic/jetpack-webpack-config/webpack' );
const CopyWebpackPlugin = require( 'copy-webpack-plugin' );

module.exports = [
	{
		entry: {
			// Video block
			'block-editor/blocks/video/index': './src/client/block-editor/blocks/video/index.ts',
			'block-editor/blocks/video/view': './src/client/block-editor/blocks/video/view.ts',

			'lib/token-bridge': './src/client/lib/token-bridge/index.ts',
			'lib/player-bridge': './src/client/lib/player-bridge/index.ts',

			'lib/videopress-token-bridge': './src/client/lib/videopress-token-bridge.js',

			// VideoPress dashboard page
			'admin/index': './src/client/admin/index.js',

			// Block editor extensions
			'block-editor/index': './src/client/block-editor/index.ts',
		},
		mode: jetpackWebpackConfig.mode,
		devtool: jetpackWebpackConfig.isDevelopment ? 'source-map' : false,
		output: {
			...jetpackWebpackConfig.output,
			path: path.resolve( './build' ),
		},
		optimization: {
			...jetpackWebpackConfig.optimization,
		},
		resolve: {
			...jetpackWebpackConfig.resolve,
		},
		node: false,
		plugins: [
			...jetpackWebpackConfig.StandardPlugins( {
				DependencyExtractionPlugin: { injectPolyfill: true },
			} ),
			new CopyWebpackPlugin( {
				patterns: [
					{
						context: 'src/client/block-editor/blocks',
						from: './*/block.json',
						to: './block-editor/blocks/[path]/[name].json',
					},
					{
						from: 'src/client/block-editor/extensions/index.json',
						to: './block-editor/extensions/index.json',
					},
				],
			} ),
		],
		module: {
			strictExportPresence: true,
			rules: [
				// Transpile JavaScript
				jetpackWebpackConfig.TranspileRule( {
					exclude: /node_modules\//,
				} ),

				// Transpile @automattic/jetpack-* in node_modules too.
				jetpackWebpackConfig.TranspileRule( {
					includeNodeModules: [ '@automattic/jetpack-' ],
				} ),

				// Handle CSS.
				jetpackWebpackConfig.CssRule( {
					extensions: [ 'css', 'sass', 'scss' ],
					extraLoaders: [
						{
							loader: 'postcss-loader',
							options: {
								postcssOptions: { config: path.join( __dirname, 'postcss.config.js' ) },
							},
						},
						'sass-loader',
					],
				} ),

				// Handle images.
				jetpackWebpackConfig.FileRule(),
			],
		},
		externals: {
			...jetpackWebpackConfig.externals,
			jetpackConfig: JSON.stringify( {
				consumer_slug: 'jetpack-videopress',
			} ),
		},
	},
];
