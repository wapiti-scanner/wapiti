# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.10] - 2023-05-01
### Changed
- Internal updates.

## [0.13.9] - 2023-04-25
### Added
- VideoPress: add is_videopress_url() helper function [#30142]
- VideoPress: add play button when the video block show controls and Preview On Hovwer is enabled [#30224]
- VideoPress: autoplay video also when Preview On Hover is enabled [#30181]
- VideoPress: integrate video poster with Preview On Hover effect [#30184]
- VideoPress: return the player control after user interaction [#30165]
- VideoPress block: Sync metadata when post is manually saved on native [#30131]

### Changed
- Updated package dependencies. [#30015]
- VideoPress: change max duration of the Preview On Hover effect to ten seconds [#30183]
- VideoPress: enqueue IFrame API file based on the embed_oembed_html filter [#30154]
- VideoPress: fix visual issue in the poster integration with Preview On Hover [#30208]
- VideoPress: iterated over autoplay + PreviewOnHover effect [#30214]
- VideoPress: Move out from Stats class [#30194]
- VideoPress: playback at beginning when Preview On Hover is enabled [#30234]

### Removed
- VideoPress: Remove poster frame update on preview play [#30217]

### Fixed
- Fix native player aspect ratio after uploading a video [#30071]
- VideoPress: Pause poster preview video when necessary [#30123]
- VideoPress block: Cover case of GUID being empty after upload finish. [#30130]
- VideoPress block: Fix blocking state when stopping an upload [#30244]
- VideoPress block: Stop saving HTML markup representation. [#30134]

## [0.13.8] - 2023-04-17
### Added
- VideoPress: add Utils PHP class [#30033]
- VideoPress: remove duplicated code when saving video block [#29993]
- VideoPress: Update poster frame by playing preview video [#30022]
- VideoPress block: Add support for fetching VideoPress metadata on native. [#29997]
- VideoPress block: Implement metadata syncing on native [#29996]

### Changed
- Refactor native Player component to handle the embed preview [#30062]
- Updated package dependencies. [#30019]
- VideoPress: do not save video block representation [#30081]
- VideoPress: render VideoPress video block 100% dynamically [#30036]
- VideoPress block: Migrate native TS files to JS files. [#29894]

### Fixed
- Disable zoom on native player [#30020]
- VideoPress: check guid attribute before to get the VideoPress video url [#30090]
- VideoPress: fix helper VideoPress function when generating URL [#30035]
- VideoPress: Fix minimum starting point for preview on hover feature with very short videos [#29994]
- VideoPress: fix setting front-end css file issue for the VideoPress video block [#30016]

## [0.13.7] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]
- VideoPress: Add fallback for experimental features for hover preview [#29974]
- VideoPress: add help to the "Starting point" range control [#29950]
- VideoPress: add marksEvery to the TimestampControl component [#29955]
- VideoPress block: Add token to play private videos. [#29933]

### Changed
- VideoPress: Do not force-enable the Stats module inside the VideoPress plugin. [#29966]
- VideoPress: expose the Preview On Hover data dynamically [#29939]
- VideoPress: set video player position according to "starting point" and "duration" [#29954]
- VideoPress: support tooltip in TimestampControl component [#29967]
- VideoPress: turn playback "controls" off when pOH feature is enabled [#29949]
- VideoPress block: Divide poster functionality from the useSyncMedia hook into a smaller hook. [#29973]

## [0.13.6] - 2023-04-05
### Added
- VideoPress: change the way to propagate the Preview On Hover data [#29912]
- VideoPress: check if beta extensions are enabled when saving VideoPress video block [#29926]
- VideoPress: enqueue the VideoPress IFrame API asset file [#29912]
- VideoPress: first previewOnHover implementation in the front-end [#29912]
- VideoPress block: Add native version of `getMediaToken` function to fetch the VideoPress token. [#29756]

### Changed
- VideoPress: update URL and add version when enqueuing VideoPress IFrame API file [#29923]

### Fixed
- VideoPress: Add empty native version of `PosterPanel` component. [#29943]
- VideoPress: Fix minimum loop duration and default hover values [#29925]

## [0.13.5] - 2023-04-04
### Added
- Add video caption to native player [#29765]
- VideoPress: Added stats endpoint to fetch the data to be featured on the My Jetpack screen. [#29785]
- VideoPress: Add video duration to block attributes [#29788]
- VideoPress: Add video preview on hover options to poster and preview panel [#29781]
- VideoPress: Persist hover preview values on markup for video block [#29883]
- VideoPress: play/pause video when previewOnHover is enabled [#29790]
- VideoPress: replace local state by using block attributes for the PreviewOnHover feature [#29807]
- VideoPress: support autoplay playback option when previewOnHover is enabled [#29816]

### Changed
- Updated package dependencies. [#29854, #29857]
- VideoPress: avoid using local state to deal with previewOnHover data [#29821]
- VideoPress: Change hover preview loop duration component to Timestamp control and fix default values [#29819]
- VideoPress: extract, create and expose usePlayerReady() hook [#29777]
- VideoPress: Fix the permission check for the VideoPress stats APIs, to check for manage_options capability. [#29820]
- VideoPress: handle limit-loop duration of the previewOn based on starting point [#29876]
- VideoPress: handle max value of the TimestampControl component [#29852]
- VideoPress: pause player when previewOnHover enables [#29843]
- VideoPress: pick duration from block attribute instead of listening player client [#29830]
- VideoPress: playback video into the boundaries defined the previewOnHover [#29892]
- VideoPress: store and control TimestampControl value externally [#29828]
- VideoPress block: Refactor useSyncMedia hook [#29898]

### Fixed
- Disable autoplay in the native editor [#29823]
- VideoPress: fix debounced callback TimestampControl issue [#29850]
- VideoPress: Retry video data fetch if data is not fully available yet [#29907]
- VideoPress block: Address the case of closing/re-opening post with an ongoing video upload. [#29690]

## [0.13.4] - 2023-04-03
### Changed
- Internal updates.

## [0.13.3] - 2023-03-29
### Added
- VideoPress: generate video image when selecting poster from frame [#29738]
- VideoPress: handle poster image generation state [#29746]

### Changed
- VideoPress: use WP COM API to generate poster image for simple sites [#29761]

## [0.13.2] - 2023-03-27
### Added
- Add basic native supported player [#29478]
- VideoPress: Added Stats module to the list of enabled modules for the standalone VP plugin. [#29668]
- VideoPress: add frame selector to Poster panel [#29688]
- VideoPress: store poster data into video block attribute [#29718]
- VideoPress block: Add Privacy and Rating panel to native block's settings. [#29477]
- VideoPress block: Add replace functionality for the native version of the block. [#29662]

### Changed
- VideoPress: trigger video events to client via player-bridge [#29617]
- VideoPress: tweak and rename poster panel title [#29711]
- VideoPress block: Tweak the label for the "Playback Bar Color" setting for clarity [#29625]

### Fixed
- Avoid conflicts with Better Click To Tweet plugin [#29681]
- VideoPress: fix computing decimal part in the TimestampControl component [#29629]
- VideoPress: Fix TimestampControl input width and mobile UI [#29639]
- VideoPress block: Fix for the case when video upload finishes outside the editor (iOS only). [#29620]
- VideoPress block: Get VideoPress GUID from a different metadata property in iOS. [#29612]

## [0.13.1] - 2023-03-22
### Added
- VideoPress: add decimalPlaces to the TimestampControl component [#29594]
- VideoPress block: Add playback bar color settings to native settings. [#29567]
- VideoPress block: Add playback panel to native block's settings. [#29457]

### Changed
- VideoPress: polish TimestampControl component styles [#29601]

### Fixed
- VideoPress block: Fix inserting item from media library. [#29476]

## [0.13.0] - 2023-03-20
### Added
- VideoPress: add async helper fn to request video poster [#29494]
- VideoPress: add disabled and autoHideTimeInput props to TimestampControl component [#29449]
- VideoPress: add helper function to request update the VideoPress video poster [#29487]
- VideoPress: add label and help properties support for the TimestampControl component [#29454]
- VideoPress block: Adds basic upload functionality to native version. [#29461]

### Changed
- Consolidate VideoPreview type [#29447]
- General: update deprecated core prop [#29463]
- Replace placeholder with loading placeholder component from js-packages [#29271]
- Updated package dependencies. [#29471]
- Updated package dependencies. [#29480]
- VideoPress: delay Done button activation to mitigate the chance of a race condition when saving the post too fast. [#29493]
- VideoPress: get rid of script const / component prop [#29466]
- VideoPress: Update comment on deprecated prop to mark it for later change [#29541]
- VideoPress block: Add details panel to native block's settings. [#29283]
- VideoPress block: Handle failed uploads. [#29511]

### Removed
- VideoPress: Remove storage meter for atomic sites [#29446]

### Fixed
- VideoPress: Add check to remove tracks from previous video after replacement on block [#29488]
- VideoPress: Fix video details form change detection [#29519]
- VideoPress: Fix video library displaying arbitrary video in first page [#29523]
- VideoPress block: Only open upload options automatically when the block is inserted from the block inserter menu. [#29515]

## [0.12.1] - 2023-03-13
### Added
- VideoPress: Add download button to video details page [#29403]
- VideoPress: add fineAdjusment to TimestampControl component [#29439]
- VideoPress: add story for PosterPanel component [#29398]
- VideoPress: first approach of TimestampControl component [#29358]

### Changed
- VideoPress: add Range control to the Timestamp control component [#29368]
- VideoPress: Move is_private and private_enabled_for_site fields to the jetpack_videopress property on the media endpoint response. [#29404]
- VideoPress: Separate loading states in video details page and disable redirect on save [#29369]
- VideoPress: set video URL based on the video privacy [#29389]
- VideoPress: Update isPrivate video property on state after privacy changes. [#29421]
- VideoPress block: Add settings toggle to native block. [#29248]

### Fixed
- VideoPress: Fix filename with token [#29395]
- VideoPress: Fix video URL available to copying in video details page [#29370]

## [0.12.0] - 2023-03-08
### Added
- VideoPress: add caption control to video block toolbar [#29233]
- VideoPress: add chapters generation from description to dashboard [#29155]
- VideoPress: add story for the Banner component [#29296]
- VideoPress: add support to "private" as site default privacy on public Atomic sites. [#29104]
- VideoPress: Add video delete action to details page [#29161]
- VideoPress: Disable the video's privacy toggle on the VideoPress dashboard for private Atomic sites. [#29169]

### Changed
- Add usePreview hook [#29164]
- Updated package dependencies. [#29216]
- VideoPress: rewrite player by using TypeScript [#29226]

### Fixed
- VideoPress: fix requesting video data on Simple sites [#29261]

## [0.11.0] - 2023-02-28
### Added
- Added support for the `preload` or `preloadcontent` attribute to the VideoPress shortcode. [#28865]
- VideoPress: add a note about __experimentalGroup InspectorControls property [#29152]
- VideoPress: add player-bridge. Update player loading state [#29057]
- VideoPress: add Poster panel to video block sidebar [#29150]
- VideoPress: move the Playback Bar color panel into the colors panel group [#29054]
- VideoPress: set poster height in block sidebar based on video ratio [#29173]

### Changed
- Updated package dependencies. [#29117]
- VideoPress: tweak Remove poster button [#29157]

### Removed
- VideoPress: removed deprecated wp-block-bridge lib [#29107]
- VideoPress: remove uploading image for video poster when uploading video [#29183]

## [0.10.12] - 2023-02-20
### Added
- VideoPress: flush token when the requester retries [#28930]
- VideoPress: improve requesting data for private videos [#28797]
- VideoPress: propagate custom CSS from VideoPress video block to core/embed when transforming block [#29035]

### Changed
- Auto-formatting of some files. [#28516]
- VideoPress: enqueue video block assets by using the Assets class [#28965]
- VideoPress: fix detecting auto-generated issue [#28945]
- VideoPress: tweak poster control styles [#29033]

### Fixed
- VideoPress: Fix dashboard fatal mistake when reading malformed local video [#29011]

## [0.10.11] - 2023-02-15
### Fixed
- VideoPress: Disable local library upload button when video is already uploaded (mobile) [#28958]

## [0.10.10] - 2023-02-15
### Added
- VideoPress: Register block for native [#28812]

### Changed
- Update to React 18. [#28710]
- VideoPress: do not use JS template to build queryString of the chapter file to avoid concat_js=no issues [#28915]

### Fixed
- VideoPress: Fix custom CSS classes removal [#28882]
- VideoPress: Fix image URLs in the block editor [#28852]

## [0.10.9] - 2023-02-08
### Added
- Add allow download option to VideoPress videos in VP dashboard [#28804]
- Add preload toggle to VideoPress block [#28705]
- VideoPress: anticipate privacy state of the video [#28664]
- VideoPress: Enforce chapters restrictions on description parsing [#28731]
- VideoPress: handle VideoPress module connection from video block [#28722]
- VideoPress: re-write token bridge lib [#28659]
- VideoPress: set isPravate attribute based also on private_enabled_for_site [#28769]

### Changed
- Updated package dependencies. [#28682]
- Updated package dependencies. [#28700]
- VideoPress: do not depend on window.wp.media in getMediaToken() lib [#28660]
- VideoPress: enqueue extensions when registrant plugin is active [#28717]
- VideoPress: improve requesting video data [#28663]

### Fixed
- VideoPress: Fix fatal error when local video cannot be read [#28817]
- VideoPress: Fix token bridge issue in development environment [#28788]

## [0.10.8] - 2023-01-30
### Added
- VideoPress: Add video chapters validation function [#28628]

### Changed
- VideoPress: change how we detect search parameters on the home page to prevent the stuck edit video details page [#28611]
- VideoPress: fix loading state bug on VideoPress video library when the query string parameters are `page=1` [#28627]
- VideoPress: replace the usage of useContext() by local helper function [#28618]

### Fixed
- VideoPress: fix error when uploading tracks in Atomic sites [#28597]

## [0.10.7] - 2023-01-26
### Added
- VideoPress: show Connect banner above video player when the site is not connected [#28585]

### Changed
- Use `flex-end` instead of `end` for better browser compatibility. [#28530]
- VideoPress: change the logic to enqueue video block scripts [#28564]

## [0.10.6] - 2023-01-25
### Changed
- VideoPress: Refactor video data check when populating block attributes [#28566]
- VideoPress: Show site default privacy setting in video block control [#28553]

## [0.10.5] - 2023-01-23
### Added
- VideoPress: add connect banner when user is not connected [#28501]
- VideoPress: do not prompt to convert embed block to VideoPress video block [#28474]
- VideoPress: do not request video data when user is not connected [#28493]
- VideoPress: improve buildVideoPressURL(). Add tests. [#28465]

### Changed
- Block bundling: sunset existing methods in favor of new `JETPACK_BLOCKS_VARIATION` constant [#28390]
- VideoPress: Prevent flash of initial state when there are search params [#28528]
- VideoPress: remove undesired border of the video player [#28484]
- VideoPress: tweak uploader layout of the VideoPress video block [#28482]

### Fixed
- VideoPress: fix replace video by uploading a new file issue [#28451]

## [0.10.4] - 2023-01-18
### Added
- VideoPress: check source language length of the video chapters [#28406]

## [0.10.3] - 2023-01-16
### Added
- VideoPress: add anchor support to VideoPress video block [#28377]
- VideoPress: add rating selector on video details edit page [#28347]

### Changed
- VideoPress: avoid requesting unneeded preview when block mounts [#28311]
- VideoPress: fix exception when deleting last video of page [#28281]
- VideoPress: skip rating checking when pulling video data for the block [#28374]
- VideoPress: tweak the footer of the uploader component [#28337]
- VideoPress: use @wordpress/html-entities to handle html entities [#28376]

### Fixed
- VideoPress: enhance behavior when deleting multiple videos [#28302]
- VideoPress: fix render player once file uploads issue [#28296]
- VideoPress: fix setting title when uploading video file [#28329]
- VideoPress: render properly title and description inputs of the video block [#28341]

## [0.10.2] - 2023-01-11
### Added
- VideoPress: add Cancel button to uploading file component when replacing file [#28188]
- VideoPress: add Replace control to video block [#28162]
- VideoPress: minor TS enhancement in the useSearchParams() hook [#28250]
- VideoPress: re-implemnt useResumableUploader(). 
  VideoPress: Iterate over resumable file uploader
    * Re implement useResumableUploader() hook with TS
    * Update VideoPress uploader to use this hook
    * Update getMediaToken() to support jwt-upload one
    * Fixes VideoPress: Editor hits the jwt endpoint unneeded #28131
    * Move upload to resumableFileUploader()
    * More TypeScript Changes [#28135]
- VideoPress: re-write VideoPress block with TypeScript [#28229]
- VideoPress: Route search query parameter so search results can be shared. [#28064]
- VideoPress: set block video by providing a GUID value [#28233]
- VideoPress: Support replace the video by setting an URL from the replace control [#28221]

### Changed
- Updated package dependencies. [#28127]
- Updated package dependencies. [#28128]
- Updated package dependencies. [#28129]
- Updated package dependencies. [#28268]
- Updated package dependencies. [#28278]
- VideoPress: set video URL in the Replace control based on the privacy [#28239]
- VideoPress: Support edit privacy on edit details page [#28240]
- VideoPress: TS enhancements in use Video data hooks [#28143]
- VideoPress: update libs used to upload a video in the dashboard context [#28163]
- VideoPress: Update no video dashboard UI to have one CTA [#28236]

### Removed
- VideoPress: remove video chapters block [#28206]

### Fixed
- VideoPress: Adjust number of placeholders when loading [#28165]
- VideoPress: change the way to detect when the media is a File instance [#28194]
- VideoPress: clean video attributes that are not options when replacing the video file [#28249]
- VideoPress: fix duplicating uploaded file when replacing the video [#28196]
- VideoPress: Fix local video listed as VideoPress video [#28237]

## [0.10.1] - 2023-01-02
### Fixed
- VideoPress: fix plugin presence check and default height. [#28083]

## [0.10.0] - 2022-12-27
### Added
- VideoPress: add core/embed transform from/to video block [#27979]
- VideoPress: Add videopress shortcode [#27842]
- VideoPress: improve blocks building process [#28025]
- VideoPress: show error notice when updating data video fails [#27992]
- VideoPress: sync video `post_id` with block attribute `id` [#27864]

### Changed
- Fix layout visual issues [#28055]
- Updated package dependency. [#28006]
- VideoPress: do not convert core/embed to videopress/video on-the-fly [#27942]

### Removed
- VideoPress: remove video editor.js unused file [#28060]

## [0.9.2] - 2022-12-19
### Changed
- VideoPress: filter the video fields that re-renders the player when changed. [#27862]

## [0.9.1] - 2022-12-19
### Changed
- Updated package dependencies. [#27887, #27888, #27916]
- Update Jetpack VideoPress logo. [#27807]
- VideoPress: set fill property of the VideoPress video icons. [#27865]

### Removed
- Remove src/client files from final bundle. [#27926]

## [0.9.0] - 2022-12-12
### Added
- Ignore .vscode/ folder [#27794]
- VideoPress: Add "Show video sharing menu" control to VideoPress block [#27784]
- VideoPress: Add first video popover [#27714]
- VideoPress: Handle URL pagination for video list/grid so every page has it's own URL. [#27813]

### Changed
- VideoPress: do not prompt to convert core/embed to videopress/video for Simple sites [#27839]

### Fixed
- VideoPress: fix issue when detecting autogenerated video track [#27814]
- VideoPress: fix issue when setting the video block video from the media library [#27799]
- VideoPress: fix removing and uploading video tracks on Simple sites [#27810]
- VideoPress: set v1.1/videos endpoint as global when requesting video data [#27804]

## [0.8.4] - 2022-12-06
### Changed
- Updated package dependencies. [#27340]

### Fixed
- VideoPress: Use the filter state to check/uncheck the checkboxes associated to each filter value. [#27744]

## [0.8.3] - 2022-12-02
### Added
- VideoPress: add debug() tool. Improve in-sync process [#27669]
- VideoPress: handle overwriting video track file [#27633]
- VideoPress: re-render player after a new track uploads [#27713]
- VideoPress: refresh UI when video track deletes [#27646]
- VideoPress: show a static image when the block acts as an example [#27686]
- VideoPress: update tracks list once new track uploads [#27704]
- VideoPress: upload track file to VideoPress server [#27631]

### Changed
- Updated package dependencies. [#27688]
- VideoPress: Disable delete_posts capability for VideoPress attachments if user is disconnected. [#27665]
- VideoPress: do not set icon color at SVG markup level [#27687]
- VideoPress: fix visual issue in Track list component when no tracks [#27648]
- VideoPress: handle properly when adding or replacing new video track [#27716]
- VideoPress: re-implement track control using ToolbarDropdownMenu [#27635]
- VideoPress: refresh video player when deleting track [#27649]
- VideoPress: remove Preload playback control from the video block sidebar [#27701]
- VideoPress: update tracks icon [#27650]

### Removed
- VideoPress: Remove caption field from edit page [#27718]

### Fixed
- Fixes issue where video meta could not be saved on a WP.com simple site. [#27725]
- VideoPress: Fix the thumbnail selection to allow selecting the last frame of the video. [#27638]
- VideoPress: fix video block conversion issue [#27678]

## [0.8.2] - 2022-11-28
### Added
- VideoPress: add example image to the dynamic colors panel [#27599]
- VideoPress: add JITM wrapper [#27579]
- VideoPress: add TrackForm component [#27627]
- VideoPress: check auto-generated chapters file [#27544]
- VideoPress: expose the array of VideoPress settings on the client initial state. [#27596]
- VideoPress: implement tracks control implementation [#27578] [#27595]

### Changed
- Updated package dependencies. [#27575]
- VideoPress: improve inline explanation for block panel options [#27563]
- VideoPress: include videos with Site Default privacy setting on the search results, choosing between the public or private filter based on the site default privacy setting. [#27603]
- VideoPress: use a generic filter message when there are no videos available and a search term is not present. [#27580]

### Fixed
- VideoPress: Fix go back link width [#27602]

## [0.8.1] - 2022-11-22
### Added
- Added VideoPress feedback link to the VideoPress block. [#27450]
- VideoPress: add "Details panel" to v6 [#27428]
- VideoPress: Add "learn how" chapters modal [#27438]
- VideoPress: add block editor dependencies [#27489]
- VideoPress: add dimensions panel to video block [#27520]
- VideoPress: add rating control to Details panel [#27415]
- VideoPress: check $products data before to pick the prices [#27504]
- VideoPress: fix issue when setting video privacy [#27435]
- VideoPress: implement "Allow download" control to v6 [#27420]
- VideoPress: implement Privacy control [#27401]
- VideoPress: improve when re-rendering the video player [#27546]
- VideoPress: register and sync isPrivate block attribute [#27493]
- VideoPress: Sync video tracks data in video block [#27495]
- VideoPress: Updated the list of plans that have VideoPress included. [#27536]

### Changed
- Updated package dependencies. [#26069]
- Updated package dependencies. [#26736]
- Updated package dependencies. [#27043]
- VideoPress: exposed the site purchases list on the client initial state, dropping the need of a request to the My Jetpack purchases endpoint. [#27533]
- VideoPress: Remove extra resize circle on block [#27498]
- VideoPress: show pricing based on sale coupons [#27535]
- VideoPress: switch to v1.1/videos when requesting video data [#27488]
- VideoPress: TypeScriptify code [#27419]

### Fixed
- VideoPress: Add backend verification on update routes when user is disconnected [#27455]
- VideoPress: Add Jetpack Complete plan to list of valid purchased plans [#27500]
- VideoPress: Disable actions when user is not connected or there is no connected site owner [#27402]
- VideoPress: fix product plan [#27502]
- VideoPress: Fix video getter function call [#27534]
- VideoPress: Remove storage meter on free plan [#27549]
- VideoPress: Set a static list of allowed video extensions allowed on VideoPress. [#27457]
- VideoPress: Set the playback token on the video URL and the new poster URL when the video needs it. [#27404]

## [0.8.0] - 2022-11-14
### Added
- VideoPress: add Color Panel component [#27381]
- VideoPress: add file drop support after first video [#27297]
- VideoPress: connect UI of settings section with the data handling. [#27350]
- VideoPress: create endpoints to fetch and update the VideoPress settings. [#27293]
- VideoPress: create selector/resolver machinery to fetch VideoPress site privacy setting from the backend. [#27321]
- VideoPress: enable thumbnail selection from video frame on quick action [#27364]
- VideoPress: exposed video_is_private flag on each video, taking into account the video privacy setting as well as the VideoPress site-wide privacy setting. [#27349]
- VideoPress: mitigate video re-rendering flicker [#27305]

### Changed
- Updated package dependencies. [#27289]
- VideoPress: allow keyboard navigation on video quick actions [#27378]
- VideoPress: allow selection of multiple files [#27357]
- VideoPress: introduce PlaybackControl component [#27303]
- VideoPress: remove the fallback video [#27315]
- VideoPress: rename Match video title with Dynamic color [#27385]
- VideoPress: show Settings only when connected [#27361]
- VideoPress: unify file drag and drop UI [#27348]

### Fixed
- VideoPress: fix an issue with private VideoPress videos timing out when script loading is delayed. [#27211]
- VideoPress: change the resolver to rely on the new needsPlaybackToken flag when deciding if a video needs a playback token. [#27380]
- VideoPress: disable automatic re-focus on video quick action popover close [#27338]
- VideoPress: fix bug and return with select thumbnail from frame [#27309]

## [0.7.0] - 2022-11-07
### Added
- Adding the new Video Chapter block. [#27240]
- Videopress: add a notice and a modal informing the users how they can create chapters. [#27244]
- VideoPress: add inspector controls to VideoPress chapters block. [#27242]
- VideoPress: add Site Settings section. [#27290]
- VideoPress: add video chapters style selector component. [#27237]
- VideoPress: add VideoPress video block select control. [#27214]
- VideoPress: introduce initial layout for chapters. [#27246]
- VideoPress: scaffolding Video Chapters block. [#27241]
- VideoPress: show message when there are no search results. [#27275]

### Changed
- Modified the VideoPress block's prompt to add a VideoChapters block so that the button functions as expected. [#27248]
- VideoPress: improve the re-rendering process of the video player when editing video props. [#27192]
- VideoPress: re-organize hooks to keep video data in sync. [#27227]

### Fixed
- VideoPress: change base number to 10 and total space value to 10^12 so we refer to it in terabytes instead of tebibytes, keeping consistency between marketing and product. [#27274]
- VideoPress: fix privacy column icon. [#27277]
- VideoPress: make sure media details are set before using them. [#27262]

## [0.6.5] - 2022-11-01
### Added
- VideoPress: add getMediaToken() async helper [#27180]
- VideoPress: add isBetaExtension() helper [#27179]
- VideoPress: add isExtensionEnabled() helper" [#27156]
- VideoPress: Add upload progress to VideoThumbnail and correct states on VideoRow [#27098]
- VideoPress: expose site-type to the client side [#27191]
- VideoPress: implement extensions (beta) handling [#27133]
- VideoPress: migrate video chapters feature from jetpack to videopress [#27178]

### Changed
- Updated package dependencies. [#27089]
- VideoPress: Change deprecated prop on VideoQuickActions [#27057]
- VideoPress: Change the playback token handling to expire tokens after 24h. [#27136]
- VideoPress: fix width of the actionable placeholder of v6 [#27099]

### Fixed
- VideoPress: Add processing state to video thumbnail on edit page [#27148]
- VideoPress: Allow actions and stats on VideoCard when processing video and fix styles [#27123]
- VideoPress: fix trying to get token when user is disconnected bug [#27067]
- VideoPress: Fix typescript issues [#27066]
- VideoPress: Get video title from backend after upload to avoid dirty form while processing [#27188]

## [0.6.4] - 2022-10-25
### Fixed
- VideoPress: Update polling time when processing [#27056]

## [0.6.3] - 2022-10-25
### Added
- VideoPress: Add component unload prevention on video details edit when there are unsaved changes [#26919]
- VideoPress: add GlobalNotice component [#26973]
- VideoPress: add loading state to connect button righ after user clicks on it [#26958]
- VideoPress: Add support to the use of playback tokens on the details page, so it's possible to see thumbnails on videos that are private. [#26996]
- VideoPress: Expose VideoPress playback token generation endpoint to enable client display of private videos and thumbnails. [#26974]
- VideoPress: give access to secondary admins [#26962]
- VideoPress: handle show admin or pricing based on a local state [#26977]
- VideoPress: handle UI when setting private video in the quick actions component [#27035]
- VideoPress: make tracks works [#27040]
- VideoPress: show an actionable notice when user connection is required [#26986]
- VideoPress: Upload from library [#26948]

### Changed
- Updated package dependencies. [#26705]
- VideoPress: Hide thumbnail actions and open library directly [#27038]
- VideoPress: show video thumbnails for private videos in the list view [#27024]

### Fixed
- VideoPress: Add check for site connectivity on video details edit page [#26969]
- VideoPress: Check for empty poster image on video polling after upload [#27000]
- VideoPress: enqueue token bridge script when `init` action [#27021]
- VideoPress: Fix unsaved changes prompt when updating video thumbnail [#26989]
- VideoPress: Remove ConnectionErrorNotice component on dashboard when there is no connection issue [#26997]

## [0.6.2] - 2022-10-19
### Added
- VideoPress: Add confirmation before leaving page when upload is in progress [#26912]
- VideoPress: Scroll to top on route change [#26915]
- VideoPress: track page view and checking out events [#26894]

### Changed
- Updated package dependencies. [#26883]
- VideoPress: change the videopress redirect value to lead to product page [#26886]

### Fixed
- VideoPress: disable upoading button when site supports paid feature [#26876]
- VideoPress: Fix focus style on ClipboardButtonInput component [#26880]
- VideoPress: fix the issue when uploading the file by dropping it off on the media placeholder [#26907]
- VideoPress: Use allowed video extensions from initial state [#26862]
- VideoPress: Use camera icon as thumbnail when the video is private. [#26898]

## [0.6.1] - 2022-10-17
### Added
- VideoPress: add an actionable dialog when the site needs connect [#26819]
- VideoPress: Allow the use of multiple values on the `videopress_rating` and `videopress_privacy_setting` filters, using comma as the separator for the values. [#26830]
- VideoPress: do not block quick actions when uploading poster image [#26853]
- VideoPress: Expose the list of blog users on the application initial state var [#26857]
- VideoPress: filter videos by Filter Section [#26845]
- VideoPress: filter videos by uploader [#26859]
- VideoPress: Loading mode for VideoRow [#26834]
- VideoPress: Persist library type [#26836]

### Changed
- Updated package dependencies. [#26851]
- VideoPress: minor FilterSection component refactoring [#26837]

### Fixed
- VideoPress: Add thumbnail and loading state when uploading poster image on video row [#26856]
- VideoPress: Extract poster image update to actions with loading meta state [#26833]
- VideoPress: fix bug when site contains local videos [#26843]

## [0.6.0] - 2022-10-13
### Added
- VideoPress: add dialog to convert core/video to videopress/video [#26768]
- VideoPress: Add poster image upload to video quick actions [#26762]
- VideoPress: Add support to `videopress_privacy_setting` and `videopress_rating` query filters to filter media attachments using the respectives meta keys. [#26777]
- VideoPress: connect videos Filter UI with the data handling [#26825]
- VideoPress: expose local videos in the initial state [#26743]
- VideoPress: first pagination approach for Local videos [#26794]
- VideoPress: implement a custom VideoPress video block recovery [#26787]
- VideoPress: reduxify local videos. first approach [#26746]
- VideoPress: reorganize and improve URL helpers [#26740]
- VideoPress: show total videos in the Local videos section [#26789]
- VideoPress: start to handle loading state for local videos [#26797]
- VideoPress: style checkout button when checking out [#26798]
- VideoPress: Surface filtering-relevant VideoPress meta keys, copying it from the attachment `videopress` metadata object to searcheable new meta key. [#26769]

### Changed
- Updated package dependencies. [#26790]
- VideoPress: move v6 core/video transfrom from VideoPress to Jetpack plugin [#26799]
- VideoPress: Pagination and search while uploading [#26780]

### Fixed
- VideoPress: Make sure the thumbnail var is set before using it to prevent "Undefined variable" notice [#26801]
- VideoPress: Thumbnail z-index [#26771]
- VideoPress: Uploading states responsive behavior [#26770]

## [0.5.1] - 2022-10-11
### Added
- VideoPress: Create new videopress/v1/site endpoint to fetch site data regardless of having the Jetpack plugin active on the target site. [#26652]
- VideoPress: handle core/oembed videopress block variation [#26735]
- VideoPress: improve UI when loading video in the frame selector modal [#26684]
- VideoPress: Include a new `no_videopress` query string parameter to remove from the list all VideoPress related media. [#26734]
- VideoPress: Provide the used storage space on the initial state data, using the site information fetched from the WPCOM API. [#26672]
- VideoPress: request site purchases to check VideoPress is supported by the site [#26630]
- VideoPress: switch privacy icon according to video privacy [#26667]

### Changed
- VideoPress: disable privacy button when updating video privacy [#26673]
- VideoPress: hide spinner in frame selector when video is loaded [#26689]
- VideoPress: Move upload data to store [#26627]
- VideoPress: Remove arrows from video quick action popovers [#26724]
- VideorPress: change the dialog message to convert from core/oembed to VideoPress video block [#26744]

### Fixed
- VideoPress: Change the endpoint used by the client to fetch the site information, so we request the storage usage from the new VideoPress-specific endpoint. [#26677]
- VideoPress: check whether the $site_data is a WP_Error instance before to het the storage used data [#26679]
- VideoPress: Fix modal layout with core gutenberg version [#26674]
- VideoPress: Fix uploaded video count update [#26651]
- VideoPress: Load data when user enter directly on edit page [#26631]
- VideoPress: Wrap the request for connection-dependent initial state data around a connection check, so we only set it when there is actually an active connection. [#26685]

## [0.5.0] - 2022-10-05
### Added
- Add the new connection error message to VideoPress. [#26579]
- VideoPress:
    - Request Product data not tied to the site
    - Expose that data to the client
    - Use them to show the price in the UI [#26538]
- VideoPress: Add loading state for dashboard [#26542]
- VideoPress: add PricingSection component [#26514]
- VideoPress: add storage meter to the Admin page [#26475]
- VideoPress: add videos stats endpoint. [#26496]
- VideoPress: connect the user from the Pricing section [#26517]
- VideoPress: do not perform async request to get videos in the first rendering [#26560]
- VideoPress: Loding mode in EditVideoDetails [#26493]
- VideoPress: Provide the list of allowed video extensions on the client initial state, fetching it from the site `get_allowed_mime_types()` list. [#26537]
- VideoPress: register the deleting video state [#26506]
- VideoPress: send initial state to the client [#26548]

### Changed
- Updated package dependencies. [#26457]
- VideoPress: Add quick actions on VideoRow for mobile [#26534]
- VideoPress: Adds the caption as a possible field on the video meta update endpoint and set the attachment post_excerpt and meta fields with it's value. [#26455]
- VideoPress: Fix filters mobile layout on dashboard library [#26518]
- VideoPress: Fix mobile style on dashboard library [#26515]
- VideoPress: Fix video edit header on mobile [#26529]
- VideoPress: Mobile layout for VideoCard component [#26491]
- VideoPress: Move upload-jwt to wpcom/v2 namespace [#26559]
- VideoPress: refresh video list right after a video is removed [#26607]

### Fixed
- Components: fix the positio of TOS component of the PricingTable cmp [#26509]
- VideoPress: Add a check for video url before rendering VideoPress block [#26578]
- VideoPress: Add thumbnail selection on video quick actions [#26612]
- VideoPress: Allows empty caption and description values so it's possible to save empty fields from the frontend. [#26564]
- VideoPress: Allows empty title value so it's possible to save empty fields from the frontend. [#26615]
- VideoPress: fix bug when deleting videos [#26553]
- VideoPress: fix current privavy of the video in the UI [#26591]
- VideoPress: fix Maximum update depth exceeded warning triggered from the useVideoDetails() hook [#26582]
- VideoPress: fix showing product price at the very first rendering [#26586]
- VideoPress: Remove button for adding new video when user cannot upload more videos [#26625]
- VideoPress: restore pagination section [#26576]
- VideoPress: Update video count on videos fetch [#26628]

## [0.4.1] - 2022-09-27
### Added
- VideoPress: add contextual upgrade trigger to dashboard. [#26403]
- VideoPress: add placeholder component. [#26478]
- VideoPress: add poster endpoint. [#26291]
- VideoPress: add sub actions to VideoQuickActions component. [#26378]
- VideoPress: add updateVideoPrivacy() action. [#26380]
- VideoPress: add uploaded video count fetch functions. [#26368]
- VideoPress: add upload jwt endpoint. [#26406]
- VideoPress: be able to remove video from the UI. [#26439]
- VideoPress: expose and store more video data. [#26369]
- VideoPress: included raw video caption on the jetpack_videopress field from the media details endpoint. [#26409]
- VideoPress: link search input load state to videos fetch state on dashboard. [#26382]
- VideoPress: set video privacy from Video Grid / dashboard. [#26405]
- VideoPress: support selecting poster by frame. [#26317]
- VideoPress: upload video from dashboard. [#26461]

### Changed
- Updated package dependencies.
- VideoPress: add file extension filter on file selection. [#26454]
- VideoPress: add VideoUploadArea component for first use screen. [#26333]
- VideoPress: hide pagination when there are less than two pages. [#26383]
- VideoPress: hit wp/v2/media to request videos data. [#26318]
- VideoPress: make Pagination work with trully data. [#26326]
- VideoPress: resolve addVideo() selector. [#26331]

### Fixed
- Set the right mapping for the caption field, relying on the new jetpack_videopress.caption raw information. [#26440]
- Set the right source for the total of videos counter on the VideoPress library page. [#26365]
- StoryBook: fix nonexistent pkg bug. [#26407]
- VideoPress: fix printing the upload video date. [#26332]
- VideoPress: fix SearchInput clear and initial typing behavior on dashboard. [#26363]
- VideoPress: fix updating the store when editing video data. [#26352]

## [0.4.0] - 2022-09-20
### Added
- VideoPress: implement filter section UI in the dashboard [#26169]
- VideoPress: Load real data at Edit Details page [#26211]
- VideoPress: sync video `description` value [#26235]
- VideoPress: update post title and content via the /videopress/meta endpoint [#26256]
- VideoPress: Update title, description and caption at backend [#26240]

### Changed
- Updated package dependencies.
- VideoPress: expose title and description in jetpack_videopress endpoint response body [#26228]
- VideoPress: sanitize the videopress description field like a textarea [#26242]
- VideoPress: Support endAdornment in Input [#26206]

### Removed
- VideoPress: Remove chapter extraction helper function [#26209]

## [0.3.1] - 2022-09-13
### Added
- VideoPress: add onSearch() prop to SearchInput component. [#26128]
- VideoPress: add video chapters extraction helper function. [#26181]
- VideoPress: introduce FilterButton component. [#26155]
- VideoPress: introduce minimal Edit Details page. [#26150]
- VideoPress: moved jetpack_videopress REST custom field to VideoPress package. [#26140]
- VideoPress: search videos when typing on the Search component. [#26139]
- VideoPress: support type, size and label in input. [#26127]

### Changed
- Updated package dependencies. [#26176]
- VideoPress: Extract VideoDetails and VideoThumbnail from VideoCard. [#26148, 26149]
- VideoPress: fix library titles. [#26145]
- VideoPress: fix styles, add loading state and clear icon to input component. [#26158]
- VideoPress: handle how the VideoCard looks when no data is provided. [#26124]

### Fixed
- VideoPress: remove white space in VP Logo. [#26121]

## [0.3.0] - 2022-09-08
### Added
- Added for videopress videos in the media selector [#25969]
- Migrating Media Library UI snippets to pkg [#25877]
- VideoPress: Add Input and SearchInput components [#25966]
- VideoPress: add query object to the getVideos() selector [#26074]
- VideoPress: Add register_videopress_blocks() method to register all VideoPress blocks [#25901]
- VideoPress: add VideoCard component [#25992]
- VideoPress: add VideosGrid component. First approach. [#25996]
- VideoPress: Add VideoStatsGroup component [#25998]
- VideoPress: Add VideoStorageMeter component [#25936]
- VideoPress: Alpha admin page [#25905]
- VideoPress: connect data with the client app [#26073]
- VideoPress: extend the media endpoint with the jetpack_videopress_guid field [#26043]
- VideoPress: first approach of data handling [#26067]
- VideoPress: implement quick actions in the VideoCard component [#26010]
- VideoPress: Introduce VideoList component [#25898]
- VideoPress Block: allow editing of some block settings while uploading. [#24556]

### Changed
- Change VideoPress into a Hybrid product in My Jetpack [#25954]
- Require user connection to upload video [#25962]
- Updated package dependencies.
- VideoPress: Improve feedback for upload/previewing [#25952]
- VideoPress: Introduce VideoQuickActions [#26016]
- VideoPress: iterate over VideoThumbnailEdit component [#25956]
- VideoPress: rename VideosGrid component to VideoGrid [#26008]
- VideoPress: set VideoThumbnail aspect ratio. Improve stories. [#25981]
- VideoPress: split up VideoDetailsCard into two new components [#25895]
- VideoPress: Support enable and disable columns and actions at VideoRow/VideoList [#25968]

### Fixed
- Ensure passed args are integer in TUS File class [#26026]

## [0.2.1] - 2022-08-30
### Added
- Upload from Media Library in the block [#25792]
- VideoPress: Add edit dropdown menu to the VideoDetailsCard component [#25817]
- VideoPress: add Logo component [#25875]
- VideoPress: Add minColumns prop to pagination component [#25876]
- VideoPress: Add Pagination component [#25871]
- VideoPress: Introduce Checkbox component [#25893]
- Videopress: Introduce VideoRow component [#25798]
- VideoPress: minor ClipboardButtonInput story enhancement [#25808]
- VideoPress: Support edit from upload [#25849]
- VideoPress: Wrap app with ThemeProvider [#25869]
- VideoPress pkg: Add VideoDetailsCard component [#25731]
- VideoPress plugin hijacks video attachment edit page [#25732]

### Changed
- Updated package dependencies. [#25694]
- Updated package dependencies. [#25814]
- VideoPress: Fix dropdown menu position of the VideoDetailsCard component [#25860]
- VideoPress Pkg: apply changes according on the `videopress/video` name convention for the video block [#25844]

### Removed
- VideoPress: Removed isLoading prop from VideoUploadArea component [#25820]

### Fixed
- Avoid conflict with old versions of Jetpack plugin [#25925]
- Fixing initialization and error handling [#25863]
- VideoPress Pkg: Avoiding re-register the VideoPress video [#25841]
- When adding video from local library that was previously uploaded to VideoPress, check if videopress attachment still exists [#25848]

## [0.2.0] - 2022-08-23
### Added
- Add the VideoUploadArea component without functionality [#25432]
- Migrate VideoPress block to pkg [#25387]
- VideoPress: add ClipboardButtonInput component [#25730]
- VideoPress: serve a minified token bridge version in production env [#25683]
- VPBlock: Support edit from upload (V6) [#25392]

### Changed
- Initialize VideoPress admin UI from the package [#25692]
- Updated package dependencies. [#25338, #25339, #25387, #25628, #25692, #25707, #25762, #25764, #25769]
- VideoPress: capital P [#25717]
- VideoPress: move client-source files from plugin to package [#25687]
- VideoPress: move videopress-token-bridge.js to client/ folder in the VideoPress package [#25676]
- VideoPress: remove sideEffect from package.json [#25714]

### Fixed
- Only add the VideoPress bridge script when a VideoPress player will be rendered on the page. [#24985]

## [0.1.5] - 2022-08-16
### Changed
- Migrating VideoPress code from the plugin to the package [#25412]
- Moving videopress dependencies to the package [#25398]
- Updated package dependencies. [#25347]
- Updated package dependencies. [#25412]

### Fixed
- Fixed missing import for recent VideoPress namespace changes [#25638]

## [0.1.4] - 2022-08-09

- Added REST api endpoint [#25042]

## [0.1.3] - 2022-08-03
### Added
- Added REST api endpoint [#25042]

### Changed
- Updated package dependencies. [#25300, #25315]
- VideoPress: Change package textdomain [#25309]

## [0.1.2] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [0.1.1] - 2022-07-19
### Added
- Add VideoPress Options class [#25047]
- VideoPress: move oEmbed registration to VideoPress package. [#25090]
- XMLRPC class [#24997]

### Changed
- Add mirror repository information to package info. [#25071]
- Updated package dependencies. [#25047]

## 0.1.0 - 2022-07-12
### Added
- Created empty package [#24952]

[0.13.10]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.9...v0.13.10
[0.13.9]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.8...v0.13.9
[0.13.8]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.7...v0.13.8
[0.13.7]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.6...v0.13.7
[0.13.6]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.5...v0.13.6
[0.13.5]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.4...v0.13.5
[0.13.4]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.3...v0.13.4
[0.13.3]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.12...v0.11.0
[0.10.12]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.11...v0.10.12
[0.10.11]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.10...v0.10.11
[0.10.10]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.9...v0.10.10
[0.10.9]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.8...v0.10.9
[0.10.8]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.7...v0.10.8
[0.10.7]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.6...v0.10.7
[0.10.6]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.5...v0.10.6
[0.10.5]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.4...v0.10.5
[0.10.4]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.3...v0.10.4
[0.10.3]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.8.4...v0.9.0
[0.8.4]: https://github.com/Automattic/jetpack-videopress/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/Automattic/jetpack-videopress/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.5...v0.7.0
[0.6.5]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Automattic/jetpack-videopress/compare/v0.1.0...v0.1.1
