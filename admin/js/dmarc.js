/* global eauthDmarcApi */

jQuery(() => {
	const checker = EmailAuthPlugin.instance.makeChecker(
		'dmarc',
		'DMARC',
		() => `${eauthDmarcApi.check}/${EmailAuthPlugin.instance.fromDomain}`,
		null,
		(res, addFootnote) => {
			if (res.footnote) {
				addFootnote(res.footnote);
			}

			return [
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
		},
		{
			get: () => ({
				record: `_dmarc.${EmailAuthPlugin.instance.fromDomain}`,
			}),
			getFallback: (res) => res.org && `_dmarc.${res.org}`,
			type: 'From Address',
			link: '#from-address',
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'fromdomainchange',
		checker.boundCheck
	);
});
