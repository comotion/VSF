<!DOCTYPE HTML PUBLIC "-//W3C//DTD XHTML 1.0 Frameset//EN"
"http://www.w3.org/TR/html4/frameset.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">	
	<head>
		<meta http-equiv="Content-type" content="text/html; charset=UTF-8"/>
		<link rel="stylesheet" href="/static/vfwweb.css" type="text/css">
		<link rel="stylesheet" media="screen" href="/static/omnigrid.css" type="text/css" />
		<script type="text/javascript" src="/static/mootools-core-1.3.2-full-compat.js"></script>
		<script type="text/javascript" src="/static/mootools-more-1.3.2.1.js"></script>
		<script type="text/javascript" src="/static/omnigrid.js"></script>

		<title>VFW :: Logs</title>
	</head>

	<body>
		<script type="text/javascript">
			var cmu = [
				{
					header: "Date/Time",
					dataIndex: "datetime",
					dataType: "string",
				},
				{
					header: "Threat",
					dataIndex: "threat",
					dataType: "string",
				},
				{
					header: "Source IP",
					dataIndex: "clientip",
					dataType: "string",
				},
				{
					header: "URL",
					dataIndex: "url",
					dataType: "string",
					width: 400,
				},

			];

			window.addEvent("domready", function(){
				datagrid = new omniGrid("loggrid", {
					columnModel: cmu,
					buttons : [],
					url: "logs.json",
					perPageOptions: [25,50,100],
					perPage: 25,
					page: 1,
					pagination: true,
					serverSort: false,
					showHeader: true,
					alternaterows: true,
					sortHeader: false,
					resizeColumns: true,
					multipleSelection: true,
					// uncomment this if you want accordion behavior for every row
					/*
					accordion: true,
					accordionRenderer: accordionFunction,
					autoSectionToggle: false,
					*/
					width: 900,
					height: 580,
				});
				// datagrid.addEvent('click', onGridSelect);
			});

		</script>
		<center><h1>VFW :: Logs</h1></center>
		<hr size=1>
		<br>
		<div id="loggrid" ></div>
	</body>
</html>
