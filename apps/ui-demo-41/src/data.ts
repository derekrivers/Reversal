import type { Club, Competition, DemoData, Fixture, Player } from './types';

// Fictional demonstration data. These names and figures are not transcribed game data.
const attributeLabels = [
  'Acceleration', 'Aggression', 'Agility', 'Anticipation', 'Balance',
  'Bravery', 'Creativity', 'Crossing', 'Decisions', 'Determination',
  'Dribbling', 'Finishing',
  'Flair', 'Handling', 'Heading', 'Influence', 'Jumping', 'Long Shots',
  'Marking', 'Off The Ball', 'Pace', 'Passing', 'Positioning', 'Reflexes',
  'Set Pieces', 'Stamina', 'Strength', 'Tackling', 'Teamwork',
  'Technique', 'Work Rate',
] as const;

function attributesFor(position: string, seed: number): Player['attributes'] {
  return attributeLabels.map((label, index) => {
    let value = 6 + ((seed * 7 + index * 3) % 10);
    if (position === 'GK' && ['Handling', 'Reflexes'].includes(label)) value += 4;
    if (position !== 'GK' && ['Handling', 'Reflexes'].includes(label)) value = 2 + ((seed + index) % 5);
    if (position.includes('D') && ['Marking', 'Tackling', 'Positioning'].includes(label)) value += 3;
    if (position.includes('M') && ['Passing', 'Teamwork', 'Work Rate'].includes(label)) value += 2;
    if (position.includes('S') && ['Finishing', 'Off The Ball', 'Pace'].includes(label)) value += 3;
    return [label, Math.min(value, 20)] as const;
  });
}

function player(
  id: string, name: string, position: string, squadNumber: number,
  nationality: string, age: number, born: string, seed: number,
  appearances: string, averageRating: string, value: string,
  preferredFoot = 'Right',
): Player {
  return {
    id, clubId: 'brackenford', name, position, squadNumber, nationality,
    age, born, bio: `${age}-year-old ${nationality} ${position} for Brackenford Athletic.`,
    attributes: attributesFor(position, seed), preferredFoot,
    form: '7-7-6-7-7', morale: 'Good', condition: `${92 + (seed % 8)}%`,
    appearances, averageRating, value,
  };
}

const clubs: Record<string, Club> = {
  brackenford: { id: 'brackenford', name: 'Brackenford Athletic', shortName: 'Brackenford', nation: 'England', division: 'Second Division', stadium: 'Briar Lane', manager: 'Adrian Selby', balance: '£1.4M', transferBudget: '£375K' },
  northmere: { id: 'northmere', name: 'Northmere Rovers', shortName: 'Northmere', nation: 'England', division: 'Second Division', stadium: 'Mere Park', manager: 'Gareth Naylor', balance: '£960K', transferBudget: '£220K' },
  westhaven: { id: 'westhaven', name: 'Westhaven City', shortName: 'Westhaven', nation: 'England', division: 'Second Division', stadium: 'Harbour Road', manager: 'Simon Dacre', balance: '£1.1M', transferBudget: '£300K' },
  moorwick: { id: 'moorwick', name: 'Moorwick United', shortName: 'Moorwick', nation: 'England', division: 'Second Division', stadium: 'The Moor Ground', manager: 'Martin Weller', balance: '£730K', transferBudget: '£150K' },
  copperdale: { id: 'copperdale', name: 'Copperdale Town', shortName: 'Copperdale', nation: 'England', division: 'Third Division', stadium: 'Foundry Field', manager: 'Neil Fenton', balance: '£540K', transferBudget: '£95K' },
  thornby: { id: 'thornby', name: 'Thornby Rangers', shortName: 'Thornby', nation: 'England', division: 'Third Division', stadium: 'Thorn Vale', manager: 'Iain Mercer', balance: '£610K', transferBudget: '£120K' },
  seabourne: { id: 'seabourne', name: 'Seabourne AFC', shortName: 'Seabourne', nation: 'England', division: 'Third Division', stadium: 'Coast End', manager: 'Peter Hollis', balance: '£480K', transferBudget: '£80K' },
  eldersfield: { id: 'eldersfield', name: 'Eldersfield Wanderers', shortName: 'Eldersfield', nation: 'England', division: 'Third Division', stadium: 'Oak Meadow', manager: 'Colin Venn', balance: '£570K', transferBudget: '£105K' },
};

const players: Record<string, Player> = {
  'milo-fenwick': player('milo-fenwick', 'Milo Fenwick', 'GK', 1, 'English', 27, '4 March 1976', 1, '32', '7.18', '£425K'),
  'dane-rowan': player('dane-rowan', 'Dane Rowan', 'D R', 2, 'English', 24, '21 February 1979', 2, '28', '6.93', '£260K'),
  'ivan-marden': player('ivan-marden', 'Ivan Marden', 'D L', 3, 'English', 25, '7 June 1978', 3, '30', '7.03', '£310K', 'Left'),
  'tom-harker': player('tom-harker', 'Tom Harker', 'D C', 4, 'English', 29, '12 January 1974', 4, '34', '7.12', '£350K'),
  'marcus-vale': player('marcus-vale', 'Marcus Vale', 'D C', 5, 'Welsh', 26, '18 April 1977', 5, '31', '7.06', '£325K'),
  'noel-calder': player('noel-calder', 'Noel Calder', 'D M C', 6, 'Scottish', 28, '9 May 1975', 6, '29', '7.00', '£300K'),
  'owen-renshaw': player('owen-renshaw', 'Owen Renshaw', 'M R', 7, 'English', 23, '15 September 1979', 7, '27', '7.21', '£475K'),
  'leo-ashcombe': player('leo-ashcombe', 'Leo Ashcombe', 'M L', 8, 'English', 25, '24 November 1977', 8, '33', '7.08', '£390K', 'Left'),
  'soren-bellwick': player('soren-bellwick', 'Soren Bellwick', 'M C', 9, 'English', 27, '1 December 1975', 9, '32', '7.16', '£450K'),
  'cal-merrin': player('cal-merrin', 'Cal Merrin', 'AM C', 10, 'Irish', 24, '27 August 1978', 10, '29', '7.29', '£650K'),
  'finn-ellery': player('finn-ellery', 'Finn Ellery', 'S C', 11, 'English', 26, '3 May 1977', 11, '30', '7.34', '£700K'),
  'aaron-breen': player('aaron-breen', 'Aaron Breen', 'GK', 12, 'Irish', 22, '14 October 1980', 12, '8', '6.88', '£150K'),
  'ryan-hartnell': player('ryan-hartnell', 'Ryan Hartnell', 'S C', 13, 'English', 21, '30 January 1982', 13, '18 (9)', '7.02', '£275K'),
};

// Every club reachable from a fixture has a small, stable fictional squad.
// The managed club above is intentionally denser for the primary Squad journey.
const visitingPlayers: Record<string, readonly string[]> = {
  northmere: ['Hugo Penrose', 'Ellis Trinder', 'Kian Bellamy', 'Mason Torley', 'Jude Norcott', 'Alec Winstanley'],
  westhaven: ['Otis Harrow', 'Evan Bursley', 'Luca Seddon', 'Rory Gilling', 'Nico Hartley', 'Toby Sorrell'],
  moorwick: ['Arlo Pritchard', 'Jonah Firth', 'Miles Tatham', 'Theo Brunton', 'Felix Corby', 'Eli Whitlow'],
  copperdale: ['Samir Hensley', 'Isaac Crowther', 'Robin Bleakley', 'Dylan Ferrow', 'Louis Frayne', 'Benji Tatlock'],
  thornby: ['Oscar Melton', 'Harris Brindle', 'Aidan Worsley', 'Noah Carrow', 'Finn Rawley', 'Cody Halden'],
  seabourne: ['Emmett Vale', 'Quinn Darrow', 'Levi Morley', 'Bobby Haldane', 'Asher Kestrel', 'Jacob Nettle'],
  eldersfield: ['Tate Greaves', 'Freddie Carlin', 'Ivo Sanderson', 'Charlie Becket', 'Cameron Varlow', 'Reuben Thistle'],
};
const visitingPositions = ['GK', 'D R', 'D C', 'M C', 'AM L', 'S C'];
for (const [clubId, names] of Object.entries(visitingPlayers)) {
  names.forEach((name, index) => {
    const id = `${clubId}-${index + 1}`;
    players[id] = {
      ...player(id, name, visitingPositions[index], index + 1, 'English', 21 + index,
        `${3 + index} June ${1982 - index}`, 20 + index, `${12 + index * 3}`, '6.90', `£${110 + index * 45}K`),
      clubId,
      bio: `${21 + index}-year-old English ${visitingPositions[index]} for ${clubs[clubId].name}.`,
    };
  });
}

const competition: Competition = {
  id: 'north-coast-cup', name: 'North Coast Cup',
  groups: [
    { id: 'group-a', name: 'Group A', clubIds: ['brackenford', 'northmere', 'westhaven', 'moorwick'] },
    { id: 'group-b', name: 'Group B', clubIds: ['copperdale', 'thornby', 'seabourne', 'eldersfield'] },
  ],
};

const fixtures: ReadonlyArray<Fixture> = [
  { id: 'fx-2003-07-12-a1', competitionId: competition.id, phase: 'Group A', date: '2003-07-12', homeClubId: 'brackenford', awayClubId: 'westhaven', homeScore: 1, awayScore: 1, venue: clubs.brackenford.stadium },
  { id: 'fx-2003-07-12-a2', competitionId: competition.id, phase: 'Group A', date: '2003-07-12', homeClubId: 'northmere', awayClubId: 'moorwick', homeScore: 2, awayScore: 0, venue: clubs.northmere.stadium },
  { id: 'fx-2003-07-12-b1', competitionId: competition.id, phase: 'Group B', date: '2003-07-12', homeClubId: 'copperdale', awayClubId: 'seabourne', homeScore: 0, awayScore: 1, venue: clubs.copperdale.stadium },
  { id: 'fx-2003-07-12-b2', competitionId: competition.id, phase: 'Group B', date: '2003-07-12', homeClubId: 'thornby', awayClubId: 'eldersfield', homeScore: 3, awayScore: 2, venue: clubs.thornby.stadium },
  { id: 'fx-2003-07-16-a1', competitionId: competition.id, phase: 'Group A', date: '2003-07-16', homeClubId: 'brackenford', awayClubId: 'northmere', venue: clubs.brackenford.stadium },
  { id: 'fx-2003-07-16-a2', competitionId: competition.id, phase: 'Group A', date: '2003-07-16', homeClubId: 'westhaven', awayClubId: 'moorwick', venue: clubs.westhaven.stadium },
  { id: 'fx-2003-07-16-b1', competitionId: competition.id, phase: 'Group B', date: '2003-07-16', homeClubId: 'copperdale', awayClubId: 'thornby', venue: clubs.copperdale.stadium },
  { id: 'fx-2003-07-16-b2', competitionId: competition.id, phase: 'Group B', date: '2003-07-16', homeClubId: 'seabourne', awayClubId: 'eldersfield', venue: clubs.seabourne.stadium },
];

const leagueFixtures: ReadonlyArray<Fixture> = [
  { id: 'lg-2003-07-05-1', competitionId: 'second-division', phase: 'League', date: '2003-07-05', homeClubId: 'brackenford', awayClubId: 'moorwick', homeScore: 2, awayScore: 1, venue: clubs.brackenford.stadium },
  { id: 'lg-2003-07-05-2', competitionId: 'second-division', phase: 'League', date: '2003-07-05', homeClubId: 'westhaven', awayClubId: 'northmere', homeScore: 0, awayScore: 0, venue: clubs.westhaven.stadium },
  { id: 'lg-2003-07-19-1', competitionId: 'second-division', phase: 'League', date: '2003-07-19', homeClubId: 'northmere', awayClubId: 'brackenford', venue: clubs.northmere.stadium },
  { id: 'lg-2003-07-19-2', competitionId: 'second-division', phase: 'League', date: '2003-07-19', homeClubId: 'moorwick', awayClubId: 'westhaven', venue: clubs.moorwick.stadium },
  { id: 'lg-2003-07-05-3', competitionId: 'third-division', phase: 'League', date: '2003-07-05', homeClubId: 'copperdale', awayClubId: 'thornby', homeScore: 1, awayScore: 0, venue: clubs.copperdale.stadium },
  { id: 'lg-2003-07-05-4', competitionId: 'third-division', phase: 'League', date: '2003-07-05', homeClubId: 'seabourne', awayClubId: 'eldersfield', homeScore: 2, awayScore: 2, venue: clubs.seabourne.stadium },
  { id: 'lg-2003-07-19-3', competitionId: 'third-division', phase: 'League', date: '2003-07-19', homeClubId: 'eldersfield', awayClubId: 'copperdale', venue: clubs.eldersfield.stadium },
  { id: 'lg-2003-07-19-4', competitionId: 'third-division', phase: 'League', date: '2003-07-19', homeClubId: 'thornby', awayClubId: 'seabourne', venue: clubs.thornby.stadium },
];

export const demoData: DemoData = {
  managedClubId: 'brackenford', clubs, players, fixtures, leagueFixtures, competition,
  dateLabel: 'Wednesday\n16.7.03 EVE',
};
