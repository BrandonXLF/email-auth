/* global eauthSpfApi */

jQuery(($) => {
	const check = EmailAuthPlugin.instance.makeChecker(
		'spf',
		'SPF',
		() => `${eauthSpfApi.check}/${EmailAuthPlugin.instance.bounceDomain}`,
		() => {
			if (EmailAuthPlugin.instance.bounceDomain === null) {
				return {
					pass: null,
					reason: 'Unknown bounce address domain.',
				};
			}
		},
		(res) => {
			const out = [
				$('<div>').append('Result: ', $('<code>').text(res.code)),
				EmailAuthPlugin.createCommentList(res.comments, 'Comments'),
			];

			if (res.rec_dns || res.pass) {
				out.push($('<h3>').text('Suggested DNS Record'));

				if (res.rec_dns) {
					out.push(
						EmailAuthPlugin.createTxtRecord(
							EmailAuthPlugin.instance.bounceDomain,
							res.rec_dns
						),
						EmailAuthPlugin.createCommentList(
							res.rec_reasons,
							'Reasons',
							'h4'
						)
					);
				} else {
					out.push($('<div>').text('Current SPF DNS record OK.'));
				}
			}

			return out;
		},
		{
			alignment: {
				getDomain: () => EmailAuthPlugin.instance.bounceDomain,
				type: 'Bounce',
			},
		}
	);

	check();
	EmailAuthPlugin.instance.addEventListener('bouncedomainchange', check);
});
