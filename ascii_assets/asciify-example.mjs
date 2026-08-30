import { asciify } from 'asciify-engine';

const canvas = document.getElementById('ascii');

await asciify('horcrux-object.jpg', canvas, {
  options: {
    fontSize: 4,
    animationStyle: 'sparkle',
    animationSpeed: 3,
    artStyle: 'particles'
  }
});

await asciify('horcrux-object.jpg', canvas, {
  options: {
    fontSize: 4,
    accentColor: '#50a0ff',
    animationStyle: 'sparkle',
    animationSpeed: 3,
    artStyle: 'starfield'
  }
});
