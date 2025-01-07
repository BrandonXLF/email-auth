/* global eauthDmarcApi */

jQuery(($) => {
	const check = EmailAuthPlugin.instance.makeChecker(
		'dmarc',
		'DMARC',
		() => `${eauthDmarcApi.check}/${EmailAuthPlugin.instance.fromDomain}`,
		null,
		(res, status) => {
			status.append('*');

			return [
				res.footnote &&
					$('<div>')
						.attr('id', 'eauth-dkim-footnote')
						.html(`* ${res.footnote}`),
				EmailAuthPlugin.createCommentList(
					res.warnings.map((desc) => ({
						level: 'warning',
						desc,
					})),
					'Warnings'
				),
				EmailAuthPlugin.createCommentList(
					res.infos.map((desc) => ({ desc })),
					'Comments'
				),
			];
		}
	);

	check();
	EmailAuthPlugin.instance.addEventListener('fromdomainchange', check);
});
