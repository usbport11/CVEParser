<?php
  $host = "127.0.0.1";
  $dbname = "cve";
  $user = "cve";
  $pass = "cve";
  $dbconn = pg_connect("host=" .$host. " dbname=" . $dbname . " user=" . $user . " password=" . $pass);
  if(!$dbconn) {
    die("Can't connect to database: " . $dbname . ": " . pg_last_error());
  }
  $query = "select ls.id, ls.name,
      vs.name as vuln_staus, si.name as source,
      ls.published, ls.description, av.name as vector,
      ac.name as complexity, ls.base_score, bs.name as severity, ls.reference
    from list3 as ls
      left join vuln_status as vs on vs.id = ls.vuln_status_id
      left join source_identifier as si on si.id = ls.source_identifier_id
      left join attack_vector as av on av.id = ls.attack_vector_id
      left join attack_complexity as ac on ac.id = ls.attack_complexity_id
      left join base_severity as bs on bs.id = ls.base_severity_id
  ";
  $result = pg_query($query);
  if(!$result) {
    die("Query failed: " . pg_last_error());
  }
  echo "<head>";
  echo "<meta charset='UTF-8'>";
  echo "<title>CVE</title>";
  echo "<link rel='stylesheet' type='text/css' href='js/bootstrap.min.css' />
    <link rel='stylesheet' type='text/css' href='js/datatables.min.css' />
    <link rel='stylesheet' type='text/css' href='js/buttons.dataTables.min.css' />
    <script type='text/javascript' src='js/jquery-3.5.1.js'></script>
    <script type='text/javascript' src='js/jquery.dataTables.min.js'></script>
    <script type='text/javascript' src='js/dataTables.buttons.min.js'></script>
    <script type='text/javascript' src='js/buttons.colVis.min.js'></script>";
  echo "<script type='text/javascript'>
    $(document).ready(function () {
      $('#cve').DataTable({
        dom: 'lBftrtip',
        columnDefs: [{targets: 1, className: 'noVis'}],
        order: [[4, 'desc']],
        buttons: [{extend: 'colvis', columns: ':not(.noVis)'}]
      });
    });
    </script>";
  echo "</head>\n";
  echo "<body>";
  echo "<table id='cve' class='table table-striped table-bordered'>";
  echo "<thead class='thead-dark'>";
  echo "<tr><th>Id</th><th>Name</th>
    <th>Status</th><th>Source</th>
    <th>Publisched</th><th>Description</th><th>Vector</th>
    <th>Complexity</th><th>Score</th><th>Severity</th><th>References</th></tr>";
  echo "<tbody>";
  while($line = pg_fetch_array($result, null, PGSQL_ASSOC)) {
    echo "<tr>\n";
    foreach($line as $key => $value)
    {
      $val = strip_tags($line[$key]);
      echo "<td>";
      switch($key) {
        case 'reference':
          $data = json_decode($val);
          foreach($data as $elem) {
            echo $elem->url . "<br>";
          }
          break;
        case 'name':
          echo '<a href="https://nvd.nist.gov/vuln/detail/' . $val . '" target="_blank">' . $val . '</a>';
          break;
        default:
          echo $val;
      }
      echo "</td>";
    }
    echo "</tr>\n";
  }
  echo "</tbody>";
  echo "</table>";
  echo "</body></html>";
  pg_free_result($result);
  pg_close($dbconn);
?>
