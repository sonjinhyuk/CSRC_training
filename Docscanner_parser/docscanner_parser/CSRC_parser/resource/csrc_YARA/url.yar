rule find_url
{
	meta:
		description = "Find url"
	strings:
		$regex = /(http|https):\/\/([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}/i
	condition:
		$regex
}