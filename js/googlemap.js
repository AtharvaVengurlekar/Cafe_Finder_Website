// Initialize and add the map
let map;

async function initMap() {
  // The location of Uluru
  const position = { lat: -25.344, lng: 131.031 };
  // Request needed libraries.
  //@ts-ignore
  const { Map } = await google.maps.importLibrary("maps");
  const { AdvancedMarkerElement } = await google.maps.importLibrary("marker");

  // The map, centered at Uluru
  map = new Map(document.getElementById("map"), {
    zoom: 4,
    center: position,
    mapId: "DEMO_MAP_ID",
  });

  addMarker("Test", position.lat, position.lng);
}

function addMarker(cafename, lat, lng)
{
    const marker = new AdvancedMarkerElement({
        map: map,
        position: { lat: lat, lng: lng},
        title: cafename,
      });
}

initMap();