import SimpleNotice from 'components/notice/index.jsx';
import NoticeAction from 'components/notice/notice-action';
import React from 'react';

import './style.scss';

/**
 * NoticesList component
 *
 * @param {*} props - Props
 * @returns {React.Component}	- NoticesList component
 */
export default function NoticesList(
	props = { handleLocalNoticeDismissClick: null, notices: Object.freeze( [] ) }
) {
	const noticesList = props.notices.map( function ( notice ) {
		const onDismissClick = theNotice => () => {
			theNotice && props.handleLocalNoticeDismissClick( theNotice.id );
		};
		return (
			<SimpleNotice
				key={ 'notice-' + notice.id }
				status={ notice.status }
				duration={ notice.duration || null }
				text={ notice.text }
				isCompact={ notice.isCompact }
				onDismissClick={ onDismissClick( notice ) }
				showDismiss={ notice.showDismiss }
			>
				{ notice.button && (
					<NoticeAction href={ notice.href } onClick={ onDismissClick( notice ) }>
						{ notice.button }
					</NoticeAction>
				) }
			</SimpleNotice>
		);
	} );

	if ( ! noticesList.length ) {
		return null;
	}

	return (
		<div id={ props.id } className="global-notices">
			{ noticesList }
		</div>
	);
}
