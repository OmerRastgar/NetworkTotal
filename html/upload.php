<html>
<body>

<?php
/* Get the name of uploaded File */

$filename = $_FILES['file']['name'];


/* Choose where to save the upload file*/

$location = "upload/".$filename;


/* Choose where to save the upload file*/

if(move_uploaded_file($_FILES['file']['tmp_name'], $location)){
   $command = escapeshellcmd('python3 test.py');
   $output = shell_exec($command);
   header("Location: http://150.136.154.103/new.html");
   exit();
}
else{

   echo 'Error uploading file';  
}



?>

</body>


</html>
